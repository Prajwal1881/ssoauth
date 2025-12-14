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

        // --- ROBUST ID PARSING ---
        // We expect IDs like "oidc_miniorange" (Start) or "oidc_miniorange-10" (Callback)
        // We must strip the "-{tenantId}" suffix to find the configuration in the DB.
        String dbProviderId = registrationId;
        String expectedSuffix = "-" + tenantId;

        if (registrationId.endsWith(expectedSuffix)) {
            dbProviderId = registrationId.substring(0, registrationId.length() - expectedSuffix.length());
            log.debug("🔍 Callback Flow: Parsed '{}' -> DB Key '{}'", registrationId, dbProviderId);
        } else {
            log.debug("🔍 Start Flow: Using raw ID '{}'", registrationId);
        }

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
            log.error("❌ SECURITY VIOLATION: Tenant Mismatch. Config Owner: {}, Current: {}", config.getTenant().getId(), tenantId);
            return null;
        }

        log.info("✅ Found Valid Config: '{}' for Tenant: {}", dbProviderId, tenantId);

        try {
            // We pass the ORIGINAL requested registrationId to ensure Spring finds what it asked for
            // BUT we ensure it has the unique suffix so the Cache Manager treats it as unique
            String uniqueRegistrationId = registrationId;
            if (!uniqueRegistrationId.endsWith(expectedSuffix)) {
                uniqueRegistrationId = uniqueRegistrationId + expectedSuffix;
            }

            return buildClientRegistration(config, uniqueRegistrationId);
        } catch (Exception e) {
            log.error("❌ Failed to build ClientRegistration for '{}': {}", registrationId, e.getMessage(), e);
            return null;
        }
    }

    private ClientRegistration buildClientRegistration(SsoProviderConfig config, String uniqueRegistrationId) {
        validateRequiredFields(config);

        // ✅ CRITICAL FIX:
        // 1. Use 'uniqueRegistrationId' (e.g. oidc_miniorange-10) for the Registration ID (Cache Key)
        // 2. Use 'config.getProviderId()' (e.g. oidc_miniorange) for the Redirect URL (IdP Callback)
        String callbackUrl = "{baseUrl}/login/oauth2/code/" + config.getProviderId();

        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(uniqueRegistrationId)
                .clientId(config.getClientId())
                .clientSecret(config.getClientSecret())
                .clientName(config.getDisplayName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(callbackUrl) // Force the URL to match the IdP setting
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
        String nameAttr = StringUtils.hasText(config.getUserNameAttribute()) ? config.getUserNameAttribute() : "sub";
        builder.userNameAttributeName(nameAttr);

        // Endpoint Overrides
        if (StringUtils.hasText(config.getAuthorizationUri())) builder.authorizationUri(config.getAuthorizationUri());
        if (StringUtils.hasText(config.getTokenUri())) builder.tokenUri(config.getTokenUri());
        if (StringUtils.hasText(config.getUserInfoUri())) builder.userInfoUri(config.getUserInfoUri());
        if (StringUtils.hasText(config.getJwkSetUri())) builder.jwkSetUri(config.getJwkSetUri());

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