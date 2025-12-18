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
        log.debug("Tenant context validated: {}", tenantId);
        return tenantId;
    }

    @Transactional(readOnly = true)
    public List<SsoProviderConfigDto> getAllConfigs() {
        Long tenantId = getTenantIdFromContextOrFail();
        log.info("Fetching all SSO configs for tenantId: {}", tenantId);

        try {
            List<SsoProviderConfig> configs = configRepository.findByTenantId(tenantId);
            log.info("Found {} SSO configs for tenantId: {}", configs.size(), tenantId);

            return configs.stream()
                    .map(this::mapEntityToDto)
                    .collect(Collectors.toList());

        } catch (Exception e) {
            log.error("Failed to fetch SSO configs for tenantId: {}", tenantId, e);
            throw e;
        }
    }

    @Transactional(readOnly = true)
    public List<SsoProviderConfig> getAllConfigEntities() {
        Long tenantId = getTenantIdFromContextOrFail();
        log.debug("Fetching SSO config entities for tenantId: {}", tenantId);

        try {
            List<SsoProviderConfig> configs = configRepository.findAll().stream()
                    .filter(c -> c.getTenant() != null && c.getTenant().getId().equals(tenantId))
                    .collect(Collectors.toList());

            log.debug("Retrieved {} config entities for tenant {}", configs.size(), tenantId);
            return configs;

        } catch (Exception e) {
            log.error("Failed to fetch config entities for tenantId: {}", tenantId, e);
            throw e;
        }
    }

    @Transactional(readOnly = true)
    public SsoProviderConfigDto getConfigById(Long id) {
        Long tenantId = getTenantIdFromContextOrFail();
        log.info("Fetching SSO config: id={}, tenantId={}", id, tenantId);

        try {
            SsoProviderConfig config = configRepository.findByIdAndTenantId(id, tenantId)
                    .orElseThrow(() -> {
                        log.error("SSO Config not found: id={}, tenantId={}", id, tenantId);
                        return new EntityNotFoundException(
                                String.format("SSO Config not found with ID %d for your organization", id));
                    });

            if (!config.getTenant().getId().equals(tenantId)) {
                log.error("SECURITY VIOLATION: Config {} belongs to tenant {}, requested by tenant {}",
                        id, config.getTenant().getId(), tenantId);
                throw new SecurityException("Access denied to this SSO configuration");
            }

            log.debug("Successfully retrieved config id={} for tenant {}", id, tenantId);
            return mapEntityToDto(config);

        } catch (EntityNotFoundException | SecurityException e) {
            log.warn("Config retrieval failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error fetching config id={} for tenant {}", id, tenantId, e);
            throw e;
        }
    }

    @Transactional(readOnly = true)
    public Optional<SsoProviderConfig> getConfigByProviderId(String providerId) {
        Long tenantId = getTenantIdFromContextOrFail();
        log.debug("Fetching SSO config by providerId: '{}', tenantId: {}", providerId, tenantId);

        try {
            Optional<SsoProviderConfig> configOpt = configRepository.findByProviderIdAndTenantId(providerId, tenantId);

            configOpt.ifPresent(config -> {
                if (!config.getTenant().getId().equals(tenantId)) {
                    log.error("SECURITY VIOLATION: Config '{}' belongs to wrong tenant", providerId);
                    throw new SecurityException("Access denied");
                }
            });

            if (configOpt.isEmpty()) {
                log.debug("No config found for providerId: '{}' in tenant: {}", providerId, tenantId);
            } else {
                log.debug("Successfully found config for providerId: '{}'", providerId);
            }

            return configOpt;

        } catch (SecurityException e) {
            log.warn("Security violation during config lookup: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Error fetching config by providerId: '{}' for tenant: {}", providerId, tenantId, e);
            throw e;
        }
    }

    @Transactional(readOnly = true)
    public List<EnabledProviderDto> getEnabledProviders() {
        Long tenantId = getTenantIdFromContextOrFail();
        log.debug("Fetching enabled SSO providers for tenantId: {}", tenantId);

        try {
            List<SsoProviderConfig> enabledConfigs = configRepository.findByTenantIdAndEnabledTrue(tenantId);
            log.info("Found {} enabled providers for tenant: {}", enabledConfigs.size(), tenantId);

            List<EnabledProviderDto> providerDtos = new ArrayList<>();
            for (SsoProviderConfig config : enabledConfigs) {
                if (!config.getTenant().getId().equals(tenantId)) {
                    log.warn("Skipping config {} due to tenant mismatch", config.getProviderId());
                    continue;
                }

                String ssoUrl = buildSsoUrl(config);
                if (ssoUrl != null) {
                    providerDtos.add(new EnabledProviderDto(
                            config.getProviderId(),
                            config.getDisplayName(),
                            ssoUrl
                    ));
                    log.debug("Added enabled provider: {} ({})", config.getDisplayName(), config.getProviderId());
                } else {
                    log.warn("Failed to build SSO URL for provider: {}", config.getProviderId());
                }
            }

            return providerDtos;

        } catch (Exception e) {
            log.error("Failed to fetch enabled providers for tenant: {}", tenantId, e);
            throw e;
        }
    }

    @Transactional
    public SsoProviderConfigDto updateConfig(Long id, SsoProviderConfigUpdateRequest dto) {
        Long tenantId = getTenantIdFromContextOrFail();
        log.info("Updating SSO config: id={}, tenantId={}, providerId='{}'", id, tenantId, dto.getProviderId());

        try {
            SsoProviderConfig existingConfig = configRepository.findByIdAndTenantId(id, tenantId)
                    .orElseThrow(() -> {
                        log.error("Update failed - Config not found: id={}, tenantId={}", id, tenantId);
                        return new EntityNotFoundException(
                                String.format("SSO Config not found with ID %d for your organization", id));
                    });

            if (!existingConfig.getTenant().getId().equals(tenantId)) {
                log.error("SECURITY VIOLATION: Attempted to update config {} belonging to different tenant", id);
                throw new SecurityException("Access denied to this SSO configuration");
            }

            if (!existingConfig.getProviderId().equals(dto.getProviderId()) ||
                    !existingConfig.getProviderType().equals(dto.getProviderType())) {
                log.error("Attempt to change providerId or providerType for config {}", id);
                throw new IllegalArgumentException("Provider ID and Type cannot be changed");
            }

            log.debug("Sanitizing config DTO");
            sanitizeDto(dto);

            BeanUtils.copyProperties(dto, existingConfig, "id", "createdAt", "updatedAt", "clientSecret", "tenant", "ldapBindPassword");

            if (StringUtils.hasText(dto.getClientSecret())) {
                existingConfig.setClientSecret(dto.getClientSecret().trim());
                log.debug("Updated client secret for config {}", id);
            }

            if (StringUtils.hasText(dto.getLdapBindPassword())) {
                existingConfig.setLdapBindPassword(dto.getLdapBindPassword());
                log.debug("Updated LDAP bind password for config {}", id);
            }

            SsoProviderConfig updatedConfig = configRepository.save(existingConfig);
            log.info("Successfully updated config: id={}, providerId='{}'", id, dto.getProviderId());

            return mapEntityToDto(updatedConfig);

        } catch (EntityNotFoundException | SecurityException | IllegalArgumentException e) {
            log.warn("Config update failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error updating config id={} for tenant {}", id, tenantId, e);
            throw e;
        }
    }

    @Transactional
    public SsoProviderConfigDto createConfig(SsoProviderConfigUpdateRequest dto) {
        Long tenantId = getTenantIdFromContextOrFail();
        log.info("Creating new SSO config: providerId='{}', type={}, tenantId={}",
                dto.getProviderId(), dto.getProviderType(), tenantId);

        try {
            Tenant tenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> {
                        log.error("Tenant not found: {}", tenantId);
                        return new EntityNotFoundException("Tenant not found: " + tenantId);
                    });

            if (configRepository.existsByProviderIdAndTenantId(dto.getProviderId(), tenantId)) {
                log.warn("Config creation failed - providerId '{}' already exists for tenant {}",
                        dto.getProviderId(), tenantId);
                throw new IllegalArgumentException(
                        "Provider ID '" + dto.getProviderId() + "' already exists for your organization");
            }

            log.debug("Sanitizing new config DTO");
            sanitizeDto(dto);

            SsoProviderConfig newConfig = new SsoProviderConfig();
            BeanUtils.copyProperties(dto, newConfig, "id", "createdAt", "updatedAt");
            newConfig.setTenant(tenant);

            SsoProviderConfig savedConfig = configRepository.save(newConfig);
            log.info("Successfully created config: id={}, providerId='{}', type={}",
                    savedConfig.getId(), savedConfig.getProviderId(), savedConfig.getProviderType());

            return mapEntityToDto(savedConfig);

        } catch (EntityNotFoundException | IllegalArgumentException e) {
            log.warn("Config creation failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error creating config providerId='{}' for tenant {}",
                    dto.getProviderId(), tenantId, e);
            throw e;
        }
    }

    private String buildSsoUrl(SsoProviderConfig config) {
        log.debug("Building SSO URL for provider: {} (type: {})", config.getProviderId(), config.getProviderType());

        try {
            switch (config.getProviderType()) {
                case OIDC:
                    return "/oauth2/authorization/" + config.getProviderId();
                case SAML:
                    return "/saml2/authenticate/" + config.getProviderId();
                case JWT:
                    String ssoUrl = config.getJwtSsoUrl() != null ? config.getJwtSsoUrl() : "#";
                    if (ssoUrl.contains("?") && ssoUrl.contains("client_id=")) {
                        return ssoUrl;
                    }
                    String clientId = config.getClientId() != null ? config.getClientId() : "";
                    String redirectUri = config.getJwtRedirectUri() != null ? config.getJwtRedirectUri() : "";
                    String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
                    return ssoUrl + "?client_id=" + clientId + "&redirect_uri=" + encodedRedirectUri;
                case AD_LDAP:
                    return "/login/ad/" + config.getProviderId();
                default:
                    log.warn("Unknown provider type for buildSsoUrl: {}", config.getProviderType());
                    return null;
            }
        } catch (Exception e) {
            log.error("Failed to build JWT URL for provider {}", config.getProviderId(), e);
            return null;
        }
    }

    private SsoProviderConfigDto mapEntityToDto(SsoProviderConfig entity) {
        SsoProviderConfigDto dto = new SsoProviderConfigDto();
        BeanUtils.copyProperties(entity, dto);
        return dto;
    }

    public Map<String, String> parseSamlMetadata(MultipartFile file) {
        log.info("Parsing SAML metadata from uploaded file");
        Map<String, String> result = new HashMap<>();

        try {
            String xmlContent = new String(file.getBytes(), StandardCharsets.UTF_8);
            log.debug("SAML metadata file size: {} bytes", xmlContent.length());

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlContent)));

            Element root = doc.getDocumentElement();
            String entityId = root.getAttribute("entityID");
            result.put("entityId", entityId);
            log.debug("Parsed SAML entityId: {}", entityId);

            NodeList idpDescriptors = root.getElementsByTagNameNS("*", "IDPSSODescriptor");
            if (idpDescriptors.getLength() > 0) {
                Element idpDescriptor = (Element) idpDescriptors.item(0);

                NodeList ssoServices = idpDescriptor.getElementsByTagNameNS("*", "SingleSignOnService");
                String ssoUrl = "";
                for (int i = 0; i < ssoServices.getLength(); i++) {
                    Element service = (Element) ssoServices.item(i);
                    String binding = service.getAttribute("Binding");
                    String location = service.getAttribute("Location");

                    if (binding.contains("HTTP-Redirect")) {
                        ssoUrl = location;
                        break;
                    } else if (ssoUrl.isEmpty()) {
                        ssoUrl = location;
                    }
                }
                result.put("ssoUrl", ssoUrl);
                log.debug("Parsed SAML SSO URL: {}", ssoUrl);

                NodeList keyDescriptors = idpDescriptor.getElementsByTagNameNS("*", "KeyDescriptor");
                for (int i = 0; i < keyDescriptors.getLength(); i++) {
                    Element keyDesc = (Element) keyDescriptors.item(i);
                    String use = keyDesc.getAttribute("use");

                    if (use == null || use.isEmpty() || "signing".equals(use)) {
                        NodeList certs = keyDesc.getElementsByTagNameNS("*", "X509Certificate");
                        if (certs.getLength() > 0) {
                            String rawCert = certs.item(0).getTextContent().replaceAll("\\s+", "");
                            String pemCert = "-----BEGIN CERTIFICATE-----\n" +
                                    chunkString(rawCert, 64) +
                                    "\n-----END CERTIFICATE-----";
                            result.put("certificate", pemCert);
                            log.debug("Successfully parsed SAML certificate");
                            break;
                        }
                    }
                }
            }

            log.info("SAML metadata parsed successfully, extracted {} fields", result.size());
            return result;

        } catch (Exception e) {
            log.error("Error parsing SAML Metadata", e);
            throw new IllegalArgumentException("Invalid SAML Metadata file: " + e.getMessage());
        }
    }

    public String generateSpMetadata(String providerId, String baseUrl) {
        log.info("Generating SP metadata for providerId: {}, baseUrl: {}", providerId, baseUrl);

        try {
            String entityId = baseUrl + "/saml2/service-provider-metadata/" + providerId;
            String acsUrl = baseUrl + "/login/saml2/sso/" + providerId;

            String metadata = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                    "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"" + entityId + "\">\n" +
                    "    <md:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
                    "        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>\n" +
                    "        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\n" +
                    "        <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"" + acsUrl + "\" index=\"0\" isDefault=\"true\"/>\n" +
                    "    </md:SPSSODescriptor>\n" +
                    "</md:EntityDescriptor>";

            log.debug("Generated SP metadata successfully");
            return metadata;

        } catch (Exception e) {
            log.error("Failed to generate SP metadata for providerId: {}", providerId, e);
            throw e;
        }
    }

    private String chunkString(String str, int chunkSize) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < str.length(); i += chunkSize) {
            sb.append(str, i, Math.min(str.length(), i + chunkSize));
            sb.append("\n");
        }
        return sb.toString().trim();
    }

    private void sanitizeDto(SsoProviderConfigUpdateRequest dto) {
        log.debug("Sanitizing SSO config DTO fields");
        if (dto.getClientId() != null) dto.setClientId(dto.getClientId().trim());
        if (dto.getClientSecret() != null) dto.setClientSecret(dto.getClientSecret().trim());
        if (dto.getIssuerUri() != null) dto.setIssuerUri(dto.getIssuerUri().trim());
        if (dto.getAuthorizationUri() != null) dto.setAuthorizationUri(dto.getAuthorizationUri().trim());
        if (dto.getTokenUri() != null) dto.setTokenUri(dto.getTokenUri().trim());
        if (dto.getJwkSetUri() != null) dto.setJwkSetUri(dto.getJwkSetUri().trim());
    }
}