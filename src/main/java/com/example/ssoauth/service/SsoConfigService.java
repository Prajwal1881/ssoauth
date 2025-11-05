package com.example.ssoauth.service;

import com.example.ssoauth.config.TenantContext;
import com.example.ssoauth.dto.EnabledProviderDto;
import com.example.ssoauth.dto.SsoProviderConfigDto;
import com.example.ssoauth.dto.SsoProviderConfigUpdateRequest;
import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.entity.Tenant;
import com.example.ssoauth.repository.SsoProviderConfigRepository;
import com.example.ssoauth.repository.TenantRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityNotFoundException;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.Session;
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

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * Helper to get the current tenant ID (Long) or return null if on main domain.
     */
    private Long getTenantIdFromContext() {
        String subdomain = TenantContext.getCurrentTenant();
        if (subdomain == null) {
            return null; // On main domain
        }
        return tenantRepository.findBySubdomain(subdomain)
                .orElseThrow(() -> new EntityNotFoundException("Invalid tenant: " + subdomain))
                .getId();
    }

    /**
     * Helper to enable the Hibernate filter using the correct Long ID.
     */
    private Session getFilteredSession() {
        Session session = entityManager.unwrap(Session.class);
        Long tenantId = getTenantIdFromContext();

        if (tenantId != null) {
            session.enableFilter("tenantFilter").setParameter("tenantId", tenantId);
        } else {
            // This is critical for Super-Admin access
            session.disableFilter("tenantFilter");
        }
        return session;
    }

    @Transactional(readOnly = true)
    public List<SsoProviderConfigDto> getAllConfigs() {
        Long tenantId = getTenantIdFromContext();
        log.info("Fetching all SSO provider configurations as DTOs (tenant: {})", tenantId);

        Session session = getFilteredSession();
        List<SsoProviderConfigDto> dtos = configRepository.findAll().stream()
                .map(this::mapEntityToDto)
                .collect(Collectors.toList());
        session.disableFilter("tenantFilter");
        return dtos;
    }

    @Transactional(readOnly = true)
    public List<SsoProviderConfig> getAllConfigEntities() {
        Long tenantId = getTenantIdFromContext();
        log.info("Fetching all SSO provider configuration ENTITIES (tenant: {})", tenantId);

        Session session = getFilteredSession();
        List<SsoProviderConfig> configs = configRepository.findAll();
        session.disableFilter("tenantFilter");
        return configs;
    }

    @Transactional(readOnly = true)
    public SsoProviderConfigDto getConfigById(Long id) {
        Long tenantId = getTenantIdFromContext();
        log.info("Fetching SSO config by ID: {} (tenant: {})", id, tenantId);

        Session session = getFilteredSession();
        SsoProviderConfig config = configRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("SSO Config not found with ID: " + id));
        session.disableFilter("tenantFilter");
        return mapEntityToDto(config);
    }

    @Transactional(readOnly = true)
    public Optional<SsoProviderConfig> getConfigByProviderId(String providerId) {
        Long tenantId = getTenantIdFromContext();
        log.debug("Fetching SSO config by provider ID: {} (tenant: {})", providerId, tenantId);

        Session session = getFilteredSession();
        Optional<SsoProviderConfig> configOpt = configRepository.findByProviderId(providerId);
        session.disableFilter("tenantFilter");
        return configOpt;
    }


    @Transactional(readOnly = true)
    public List<EnabledProviderDto> getEnabledProviders() {
        Long tenantId = getTenantIdFromContext();
        log.debug("Fetching enabled SSO provider DTOs (tenant: {})", tenantId);

        if (tenantId == null) {
            log.debug("On main domain, returning no SSO providers.");
            return new ArrayList<>();
        }

        Session session = getFilteredSession();
        List<SsoProviderConfig> enabledConfigs = configRepository.findByEnabledTrue();
        session.disableFilter("tenantFilter");

        List<EnabledProviderDto> providerDtos = new ArrayList<>();
        for (SsoProviderConfig config : enabledConfigs) {
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
        Long tenantId = getTenantIdFromContext();
        log.info("Updating SSO config for ID: {} (tenant: {})", id, tenantId);

        Session session = getFilteredSession();
        SsoProviderConfig existingConfig = configRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("SSO Config not found with ID: " + id));
        session.disableFilter("tenantFilter");

        if (!existingConfig.getProviderId().equals(dto.getProviderId()) ||
                !existingConfig.getProviderType().equals(dto.getProviderType())) {
            log.warn("Attempted to change providerId or providerType during update for ID: {}", id);
            throw new IllegalArgumentException("Provider ID and Type cannot be changed.");
        }
        BeanUtils.copyProperties(dto, existingConfig, "id", "createdAt", "updatedAt", "clientSecret", "tenant");
        if (StringUtils.hasText(dto.getClientSecret())) {
            log.debug("Client secret is being updated for config ID: {}", id);
            existingConfig.setClientSecret(dto.getClientSecret());
        }
        SsoProviderConfig updatedConfig = configRepository.save(existingConfig);
        log.info("SSO config updated successfully for ID: {}", id);
        return mapEntityToDto(updatedConfig);
    }

    @Transactional
    public SsoProviderConfigDto createConfig(SsoProviderConfigUpdateRequest dto) {
        Long tenantId = getTenantIdFromContext();
        if (tenantId == null) {
            throw new RuntimeException("Cannot create config without tenant context.");
        }
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + tenantId));

        log.info("Creating new SSO config for provider ID: {} in tenant: {}", dto.getProviderId(), tenantId);

        Session session = getFilteredSession();
        if (configRepository.findByProviderId(dto.getProviderId()).isPresent()) {
            session.disableFilter("tenantFilter");
            throw new IllegalArgumentException("Provider ID already exists in this tenant: " + dto.getProviderId());
        }
        session.disableFilter("tenantFilter");

        SsoProviderConfig newConfig = new SsoProviderConfig();
        BeanUtils.copyProperties(dto, newConfig, "id", "createdAt", "updatedAt");
        newConfig.setTenant(tenant);

        SsoProviderConfig savedConfig = configRepository.save(newConfig);
        log.info("SSO config created successfully with ID: {}", savedConfig.getId());
        return mapEntityToDto(savedConfig);
    }

    // --- Helper Methods (Unchanged) ---

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
                    log.error("Failed to build JWT redirect URL for provider {}: {}", config.getProviderId(), e.getMessage());
                    return null;
                }
            default:
                log.warn("SSO URL building not supported for provider type: {}", config.getProviderType());
                return null;
        }
    }

    private SsoProviderConfigDto mapEntityToDto(SsoProviderConfig entity) {
        SsoProviderConfigDto dto = new SsoProviderConfigDto();
        BeanUtils.copyProperties(entity, dto);
        return dto;
    }
}