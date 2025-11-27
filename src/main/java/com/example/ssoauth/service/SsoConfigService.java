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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.Map;
import java.util.HashMap;
import org.springframework.web.multipart.MultipartFile;

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

    private Long getTenantIdFromContextOrFail() {
        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) {
            log.error("SECURITY VIOLATION: Attempted to access SSO config without tenant context");
            throw new SecurityException("Tenant context is required for this operation");
        }
        return tenantId;
    }

    @Transactional(readOnly = true)
    public List<SsoProviderConfigDto> getAllConfigs() {
        Long tenantId = getTenantIdFromContextOrFail();
        log.info("→ Fetching ALL SSO configs for tenantId: {}", tenantId);

        List<SsoProviderConfig> configs = configRepository.findAll().stream()
                .filter(c -> c.getTenant() != null && c.getTenant().getId().equals(tenantId))
                .collect(Collectors.toList());

        log.info("← Found {} SSO configs for tenantId: {}", configs.size(), tenantId);
        return configs.stream()
                .map(this::mapEntityToDto)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<SsoProviderConfig> getAllConfigEntities() {
        Long tenantId = getTenantIdFromContextOrFail();
        log.debug("Fetching SSO config entities for tenantId: {}", tenantId);

        return configRepository.findAll().stream()
                .filter(c -> c.getTenant() != null && c.getTenant().getId().equals(tenantId))
                .collect(Collectors.toList());
    }

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
            throw new SecurityException("Access denied to this SSO configuration");
        }

        if (!existingConfig.getProviderId().equals(dto.getProviderId()) ||
                !existingConfig.getProviderType().equals(dto.getProviderType())) {
            throw new IllegalArgumentException("Provider ID and Type cannot be changed");
        }

        BeanUtils.copyProperties(dto, existingConfig, "id", "createdAt", "updatedAt", "clientSecret", "tenant");

        if (StringUtils.hasText(dto.getClientSecret())) {
            existingConfig.setClientSecret(dto.getClientSecret());
        }

        SsoProviderConfig updatedConfig = configRepository.save(existingConfig);
        return mapEntityToDto(updatedConfig);
    }

    @Transactional
    public SsoProviderConfigDto createConfig(SsoProviderConfigUpdateRequest dto) {
        Long tenantId = getTenantIdFromContextOrFail();
        log.info("→ Creating SSO config: providerId='{}', tenantId={}", dto.getProviderId(), tenantId);

        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + tenantId));

        if (configRepository.existsByProviderIdAndTenantId(dto.getProviderId(), tenantId)) {
            throw new IllegalArgumentException(
                    "Provider ID '" + dto.getProviderId() + "' already exists for your organization");
        }

        SsoProviderConfig newConfig = new SsoProviderConfig();
        BeanUtils.copyProperties(dto, newConfig, "id", "createdAt", "updatedAt");
        newConfig.setTenant(tenant);

        SsoProviderConfig savedConfig = configRepository.save(newConfig);
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

                    // --- UPDATED LOGIC ---
                    // If the URL already contains parameters (like the full MiniOrange URL), use it as is.
                    if (ssoUrl.contains("?") && ssoUrl.contains("client_id=")) {
                        return ssoUrl;
                    }

                    // Otherwise, construct it manually (Legacy support)
                    String clientId = config.getClientId() != null ? config.getClientId() : "";
                    String redirectUri = config.getJwtRedirectUri() != null ? config.getJwtRedirectUri() : "";
                    String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
                    return ssoUrl + "?client_id=" + clientId + "&redirect_uri=" + encodedRedirectUri;
                } catch (Exception e) {
                    log.error("Failed to build JWT URL for {}: {}", config.getProviderId(), e.getMessage());
                    return null;
                }
            default:
                return null;
        }
    }

    private SsoProviderConfigDto mapEntityToDto(SsoProviderConfig entity) {
        SsoProviderConfigDto dto = new SsoProviderConfigDto();
        BeanUtils.copyProperties(entity, dto);
        return dto;
    }

    // --- NEW: SAML Metadata Handling ---

    public Map<String, String> parseSamlMetadata(MultipartFile file) {
        Map<String, String> result = new HashMap<>();
        try {
            String xmlContent = new String(file.getBytes(), StandardCharsets.UTF_8);

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true); // Important for SAML namespaces
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlContent)));

            // 1. Get Entity ID
            Element root = doc.getDocumentElement();
            String entityId = root.getAttribute("entityID");
            result.put("entityId", entityId);

            // 2. Find IDPSSODescriptor
            NodeList idpDescriptors = root.getElementsByTagNameNS("*", "IDPSSODescriptor");
            if (idpDescriptors.getLength() > 0) {
                Element idpDescriptor = (Element) idpDescriptors.item(0);

                // 3. Find SingleSignOnService (HTTP-Redirect preferred, else HTTP-POST)
                NodeList ssoServices = idpDescriptor.getElementsByTagNameNS("*", "SingleSignOnService");
                String ssoUrl = "";
                for (int i = 0; i < ssoServices.getLength(); i++) {
                    Element service = (Element) ssoServices.item(i);
                    String binding = service.getAttribute("Binding");
                    String location = service.getAttribute("Location");

                    if (binding.contains("HTTP-Redirect")) {
                        ssoUrl = location;
                        break; // Prefer Redirect
                    } else if (ssoUrl.isEmpty()) {
                        ssoUrl = location; // Fallback
                    }
                }
                result.put("ssoUrl", ssoUrl);

                // 4. Find X.509 Certificate (Signing)
                NodeList keyDescriptors = idpDescriptor.getElementsByTagNameNS("*", "KeyDescriptor");
                for (int i = 0; i < keyDescriptors.getLength(); i++) {
                    Element keyDesc = (Element) keyDescriptors.item(i);
                    String use = keyDesc.getAttribute("use");

                    // If 'use' is missing, it applies to both. If 'use' is 'signing', take it.
                    if (use == null || use.isEmpty() || "signing".equals(use)) {
                        NodeList certs = keyDesc.getElementsByTagNameNS("*", "X509Certificate");
                        if (certs.getLength() > 0) {
                            String rawCert = certs.item(0).getTextContent().replaceAll("\\s+", "");
                            // Format as PEM
                            String pemCert = "-----BEGIN CERTIFICATE-----\n" +
                                    chunkString(rawCert, 64) +
                                    "\n-----END CERTIFICATE-----";
                            result.put("certificate", pemCert);
                            break;
                        }
                    }
                }
            }
            return result;
        } catch (Exception e) {
            log.error("Error parsing SAML Metadata", e);
            throw new IllegalArgumentException("Invalid SAML Metadata file: " + e.getMessage());
        }
    }

    public String generateSpMetadata(String providerId, String baseUrl) {
        String entityId = baseUrl + "/saml2/service-provider-metadata/" + providerId;
        String acsUrl = baseUrl + "/login/saml2/sso/" + providerId;

        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"" + entityId + "\">\n" +
                "    <md:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
                "        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>\n" +
                "        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\n" +
                "        <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"" + acsUrl + "\" index=\"0\" isDefault=\"true\"/>\n" +
                "    </md:SPSSODescriptor>\n" +
                "</md:EntityDescriptor>";
    }

    private String chunkString(String str, int chunkSize) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < str.length(); i += chunkSize) {
            sb.append(str, i, Math.min(str.length(), i + chunkSize));
            sb.append("\n");
        }
        return sb.toString().trim();
    }
}