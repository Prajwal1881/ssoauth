package com.example.ssoauth.service;

import com.example.ssoauth.config.TenantContext;
import com.example.ssoauth.dto.EnabledProviderDto;
import com.example.ssoauth.dto.SsoProviderConfigDto;
import com.example.ssoauth.dto.SsoProviderConfigUpdateRequest;
import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.entity.Tenant;
import com.example.ssoauth.repository.SsoProviderConfigRepository;
import com.example.ssoauth.repository.TenantRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.List;
import java.util.ArrayList;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class SsoConfigService {

    private final SsoProviderConfigRepository configRepository;
    private final TenantRepository tenantRepository;

    /**
     * This method is for tenant-scoped operations.
     */
    private Long getTenantIdFromContextOrFail() {
        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) {
            log.error("SECURITY VIOLATION: Admin operation attempted without tenant context");
            throw new SecurityException("Tenant context is required for this operation");
        }
        return tenantId;
    }

    @Transactional(readOnly = true)
    public List<SsoProviderConfigDto> getAllConfigs() {
        Long tenantId = getTenantIdFromContextOrFail();
        log.info("→ Fetching ALL SSO configs for tenantId: {}", tenantId);

        // Use explicit tenant query
        List<SsoProviderConfig> configs = configRepository.findAll().stream()
                .filter(c -> c.getTenant() != null && c.getTenant().getId().equals(tenantId))
                .collect(Collectors.toList());

        log.info("← Found {} SSO configs for tenantId: {}", configs.size(), tenantId);
        return configs.stream()
                .map(this::mapEntityToDto)
                .collect(Collectors.toList());
    }

    // =================================================================
    // --- THIS IS THE FINAL, CORRECT METHOD ---
    // =================================================================
    /**
     * This version handles the 'null' tenantId for super-admins
     * by returning an empty list instead of throwing an exception.
     */
    @Transactional(readOnly = true)
    public List<SsoProviderConfig> getAllConfigEntities() {
        Long tenantId = TenantContext.getCurrentTenant(); // <-- Use the getter that allows null

        if (tenantId == null) {
            // Super-admin or root domain access. No tenant-specific configs.
            log.debug("getAllConfigEntities called with no tenant context (super-admin). Returning empty list.");
            return List.of(); // Return an empty list instead of throwing an error
        }

        log.debug("Fetching SSO config entities for tenantId: {}", tenantId);

        // Use explicit tenant-aware query
        return configRepository.findAll().stream()
                .filter(c -> c.getTenant() != null && c.getTenant().getId().equals(tenantId))
                .collect(Collectors.toList());
    }
    // =================================================================
    // --- END OF FIX ---
    // =================================================================

    @Transactional(readOnly = true)
    public SsoProviderConfigDto getConfigById(Long id) {
        Long tenantId = getTenantIdFromContextOrFail();
        log.info("→ Fetching SSO config: id={}, tenantId={}", id, tenantId);

        SsoProviderConfig config = configRepository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> {
                    log.error("✗ SSO Config not found: id={}, tenantId={}", id, tenantId);
                    return new EntityNotFoundException(
                            String.format("SSO Config not found with ID %d for your organization", id));
                });

        if (!config.getTenant().getId().equals(tenantId)) {
            log.error("SECURITY VIOLATION: Config {} belongs to tenant {}, but requested by tenant {}",
                    id, config.getTenant().getId(), tenantId);
            throw new SecurityException("Access denied to this SSO configuration");
        }

        log.info("✓ SSO Config found: id={}, providerId='{}', tenant={}",
                id, config.getProviderId(), tenantId);
        return mapEntityToDto(config);
    }

    @Transactional(readOnly = true)
    public Optional<SsoProviderConfig> getConfigByProviderId(String providerId) {
        Long tenantId = getTenantIdFromContextOrFail();
        log.debug("Fetching SSO config: providerId='{}', tenantId={}", providerId, tenantId);

        Optional<SsoProviderConfig> configOpt = configRepository.findByProviderIdAndTenantId(providerId, tenantId);

        configOpt.ifPresent(config -> {
            if (!config.getTenant().getId().equals(tenantId)) {
                log.error("SECURITY VIOLATION: Config '{}' belongs to wrong tenant", providerId);
                throw new SecurityException("Access denied");
            }
        });

        return configOpt;
    }

    @Transactional(readOnly = true)
    public List<EnabledProviderDto> getEnabledProviders() {
        Long tenantId = getTenantIdFromContextOrFail();
        log.debug("Fetching enabled SSO providers for tenantId: {}", tenantId);

        List<SsoProviderConfig> enabledConfigs = configRepository.findByTenantIdAndEnabledTrue(tenantId);

        List<EnabledProviderDto> providerDtos = new ArrayList<>();
        for (SsoProviderConfig config : enabledConfigs) {
            if (!config.getTenant().getId().equals(tenantId)) {
                log.warn("Skipping config {} - wrong tenant", config.getProviderId());
                continue;
            }

            String ssoUrl = buildSsoUrl(config);
            if (ssoUrl != null) {
                providerDtos.add(new EnabledProviderDto(
                        config.getProviderId(),
                        config.getDisplayName(),
                        ssoUrl
                ));
            }
        }
        return providerDtos;
    }

    @Transactional
    public SsoProviderConfigDto updateConfig(Long id, SsoProviderConfigUpdateRequest dto) {
        Long tenantId = getTenantIdFromContextOrFail();
        log.info("→ Updating SSO config: id={}, tenantId={}", id, tenantId);

        SsoProviderConfig existingConfig = configRepository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> {
                    log.error("✗ Update failed - Config not found: id={}, tenantId={}", id, tenantId);
                    return new EntityNotFoundException(
                            String.format("SSO Config not found with ID %d for your organization", id));
                });

        if (!existingConfig.getTenant().getId().equals(tenantId)) {
            log.error("SECURITY VIOLATION: Attempted to update config {} belonging to different tenant", id);
            throw new SecurityException("Access denied to this SSO configuration");
        }

        if (!existingConfig.getProviderId().equals(dto.getProviderId()) ||
                !existingConfig.getProviderType().equals(dto.getProviderType())) {
            log.warn("Attempt to change providerId or type for config {}", id);
            throw new IllegalArgumentException("Provider ID and Type cannot be changed");
        }

        BeanUtils.copyProperties(dto, existingConfig, "id", "createdAt", "updatedAt", "clientSecret", "tenant");

        if (StringUtils.hasText(dto.getClientSecret())) {
            log.debug("Updating client secret for config {}", id);
            existingConfig.setClientSecret(dto.getClientSecret());
        }

        if (StringUtils.hasText(dto.getKerberosKeytabBase64())) {
            log.debug("Updating keytab for config {}", id);
            existingConfig.setKerberosKeytabBase64(dto.getKerberosKeytabBase64());
        }

        SsoProviderConfig updatedConfig = configRepository.save(existingConfig);
        log.info("✓ SSO config updated: id={}, providerId='{}'", id, updatedConfig.getProviderId());
        return mapEntityToDto(updatedConfig);
    }

    @Transactional
    public SsoProviderConfigDto createConfig(SsoProviderConfigUpdateRequest dto) {
        Long tenantId = getTenantIdFromContextOrFail();
        log.info("→ Creating SSO config: providerId='{}', tenantId={}", dto.getProviderId(), tenantId);

        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + tenantId));

        if (configRepository.existsByProviderIdAndTenantId(dto.getProviderId(), tenantId)) {
            log.warn("Create failed - providerId '{}' already exists for tenant {}",
                    dto.getProviderId(), tenantId);
            throw new IllegalArgumentException(
                    "Provider ID '" + dto.getProviderId() + "' already exists for your organization");
        }

        SsoProviderConfig newConfig = new SsoProviderConfig();
        BeanUtils.copyProperties(dto, newConfig, "id", "createdAt", "updatedAt");
        newConfig.setTenant(tenant);

        SsoProviderConfig savedConfig = configRepository.save(newConfig);
        log.info("✓ SSO config created: id={}, providerId='{}', tenantId={}",
                savedConfig.getId(), savedConfig.getProviderId(), tenantId);
        return mapEntityToDto(savedConfig);
    }

    // --- Helper Methods ---

    private String buildSsoUrl(SsoProviderConfig config) {
        switch (config.getProviderType()) {
            case OIDC:
                return "/oauth2/authorization/" + config.getProviderId();
            case SAML:
                return "/saml2/authenticate/" + config.getProviderId();
            case JWT:
                try {
                    String ssoUrl = config.getJwtSsoUrl() != null ? config.getJwtSsoUrl() : "#";
                    String clientId = config.getClientId() != null ? config.getClientId() : "";
                    String redirectUri = config.getJwtRedirectUri() != null ? config.getJwtRedirectUri() : "";
                    String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
                    return ssoUrl + "?client_id=" + clientId + "&redirect_uri=" + encodedRedirectUri;
                } catch (Exception e) {
                    log.error("Failed to build JWT URL for {}: {}", config.getProviderId(), e.getMessage());
                    return null;
                }
            default:
                log.warn("URL building not supported for type: {}", config.getProviderType());
                return null;
        }
    }

    private SsoProviderConfigDto mapEntityToDto(SsoProviderConfig entity) {
        SsoProviderConfigDto dto = new SsoProviderConfigDto();
        BeanUtils.copyProperties(entity, dto);
        // Explicitly exclude clientSecret (it's not in the DTO)
        return dto;
    }
}