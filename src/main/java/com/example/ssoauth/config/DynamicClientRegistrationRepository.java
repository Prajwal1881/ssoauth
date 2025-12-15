package com.example.ssoauth.config;

import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.entity.SsoProviderType;
import com.example.ssoauth.service.SsoConfigService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Slf4j
public class DynamicClientRegistrationRepository implements ClientRegistrationRepository {

    private final SsoConfigService ssoConfigService;

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        Long tenantId = TenantContext.getCurrentTenant();

        if (tenantId == null) {
            log.error("❌ SECURITY ISSUE: No tenant context when looking up OIDC registration: '{}'", registrationId);
            return null;
        }

        // CRITICAL FIX: Strip tenant suffix for DB lookup, but keep it for registration ID consistency
        String dbProviderId = extractBaseProviderId(registrationId, tenantId);

        log.debug("🔍 OIDC Lookup - Requested: '{}', DB Key: '{}', Tenant: {}",
                registrationId, dbProviderId, tenantId);

        // Load configuration from database
        SsoProviderConfig config = ssoConfigService.getConfigByProviderId(dbProviderId).orElse(null);

        // Validation Checks with Logging
        if (config == null) {
            log.warn("⚠️ OIDC Config NOT FOUND in DB. Tenant: {}, ProviderID: '{}'", tenantId, dbProviderId);
            return null;
        }
        if (!config.isEnabled()) {
            log.warn("⚠️ OIDC Config is DISABLED. Tenant: {}, ProviderID: '{}'", tenantId, dbProviderId);
            return null;
        }
        if (config.getProviderType() != SsoProviderType.OIDC) {
            log.error("❌ Provider '{}' is type {} (Expected OIDC)", dbProviderId, config.getProviderType());
            return null;
        }
        if (!config.getTenant().getId().equals(tenantId)) {
            log.error("❌ SECURITY VIOLATION: Tenant Mismatch. Config Owner: {}, Current: {}",
                    config.getTenant().getId(), tenantId);
            return null;
        }

        log.info("✅ Found Valid Config: '{}' for Tenant: {}", dbProviderId, tenantId);

        try {
            // CRITICAL: Use the exact registrationId that was requested
            // This ensures consistency between authorization and callback phases
            return buildClientRegistration(config, registrationId, dbProviderId);
        } catch (Exception e) {
            log.error("❌ Failed to build ClientRegistration for '{}': {}", registrationId, e.getMessage(), e);
            return null;
        }
    }

    /**
     * CRITICAL: Extracts base provider ID by removing tenant suffix if present.
     * This allows us to use the same DB config for multiple tenants while maintaining
     * unique registration IDs internally.
     */
    private String extractBaseProviderId(String registrationId, Long tenantId) {
        String tenantSuffix = "-" + tenantId;
        if (registrationId.endsWith(tenantSuffix)) {
            return registrationId.substring(0, registrationId.length() - tenantSuffix.length());
        }
        return registrationId;
    }

    /**
     * Builds ClientRegistration with consistent registration ID handling.
     *
     * @param config The SSO provider configuration from database
     * @param registrationId The EXACT registration ID requested by Spring Security
     * @param baseProviderId The provider ID without tenant suffix (for redirect URI)
     */
    private ClientRegistration buildClientRegistration(
            SsoProviderConfig config,
            String registrationId,
            String baseProviderId) {

        validateRequiredFields(config);

        // CRITICAL FIX: Use baseProviderId for redirect URI (matches IdP configuration)
        // This allows a single redirect URI to serve all tenants
        String callbackUrl = "{baseUrl}/login/oauth2/code/" + baseProviderId;

        log.debug("Building ClientRegistration - RegID: '{}', RedirectURI pattern: '{}'",
                registrationId, callbackUrl);

        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId)
                .clientId(config.getClientId())
                .clientSecret(config.getClientSecret())
                .clientName(config.getDisplayName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(callbackUrl) // Uses base provider ID (no tenant suffix)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

        if (StringUtils.hasText(config.getIssuerUri())) {
            builder.issuerUri(config.getIssuerUri());
        }

        if (StringUtils.hasText(config.getScopes())) {
            builder.scope(Arrays.stream(config.getScopes().split(","))
                    .map(String::trim)
                    .filter(StringUtils::hasText)
                    .collect(Collectors.toSet()));
        } else {
            builder.scope("openid", "profile", "email");
        }

        // Default to 'sub' if not configured
        String nameAttr = StringUtils.hasText(config.getUserNameAttribute())
                ? config.getUserNameAttribute() : "sub";
        builder.userNameAttributeName(nameAttr);

        // Endpoint Overrides
        if (StringUtils.hasText(config.getAuthorizationUri())) {
            builder.authorizationUri(config.getAuthorizationUri());
        }
        if (StringUtils.hasText(config.getTokenUri())) {
            builder.tokenUri(config.getTokenUri());
        }
        if (StringUtils.hasText(config.getUserInfoUri())) {
            builder.userInfoUri(config.getUserInfoUri());
        }
        if (StringUtils.hasText(config.getJwkSetUri())) {
            builder.jwkSetUri(config.getJwkSetUri());
        }

        return builder.build();
    }

    private void validateRequiredFields(SsoProviderConfig config) {
        if (!StringUtils.hasText(config.getClientId())) {
            throw new IllegalArgumentException("ClientId is missing for provider: " + config.getProviderId());
        }
        if (!StringUtils.hasText(config.getClientSecret())) {
            throw new IllegalArgumentException("ClientSecret is missing for provider: " + config.getProviderId());
        }
    }
}