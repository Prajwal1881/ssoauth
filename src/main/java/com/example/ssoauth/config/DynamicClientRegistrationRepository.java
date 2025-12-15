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

        // CRITICAL: Strip tenant suffix for DB lookup, but keep it for registration ID consistency
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
            return buildClientRegistration(config, registrationId, dbProviderId);
        } catch (Exception e) {
            log.error("❌ Failed to build ClientRegistration for '{}': {}", registrationId, e.getMessage(), e);
            return null;
        }
    }

    private String extractBaseProviderId(String registrationId, Long tenantId) {
        String tenantSuffix = "-" + tenantId;
        if (registrationId.endsWith(tenantSuffix)) {
            return registrationId.substring(0, registrationId.length() - tenantSuffix.length());
        }
        return registrationId;
    }

    private ClientRegistration buildClientRegistration(
            SsoProviderConfig config,
            String registrationId,
            String baseProviderId) {

        validateRequiredFields(config);

        // CRITICAL: Use baseProviderId for redirect URI to allow a single URI to serve all tenants
        String callbackUrl = "{baseUrl}/login/oauth2/code/" + baseProviderId;

        log.debug("Building ClientRegistration - RegID: '{}', RedirectURI pattern: '{}'",
                registrationId, callbackUrl);

        // --- SECURITY FIX: TRIM WHITESPACE FROM CREDENTIALS ---
        String clientId = config.getClientId().trim();
        String clientSecret = config.getClientSecret().trim();
        // -----------------------------------------------------

        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientName(config.getDisplayName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(callbackUrl)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

        if (StringUtils.hasText(config.getIssuerUri())) {
            builder.issuerUri(config.getIssuerUri().trim()); // Trim issuer too
        }

        if (StringUtils.hasText(config.getScopes())) {
            builder.scope(Arrays.stream(config.getScopes().split(","))
                    .map(String::trim)
                    .filter(StringUtils::hasText)
                    .collect(Collectors.toSet()));
        } else {
            builder.scope("openid", "profile", "email");
        }

        String nameAttr = StringUtils.hasText(config.getUserNameAttribute())
                ? config.getUserNameAttribute().trim() : "sub";
        builder.userNameAttributeName(nameAttr);

        // Endpoint Overrides - Trim these as well
        if (StringUtils.hasText(config.getAuthorizationUri())) {
            builder.authorizationUri(config.getAuthorizationUri().trim());
        }
        if (StringUtils.hasText(config.getTokenUri())) {
            builder.tokenUri(config.getTokenUri().trim());
        }
        if (StringUtils.hasText(config.getUserInfoUri())) {
            builder.userInfoUri(config.getUserInfoUri().trim());
        }
        if (StringUtils.hasText(config.getJwkSetUri())) {
            builder.jwkSetUri(config.getJwkSetUri().trim());
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