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

/**
 * Dynamically loads OIDC (OAuth2) client configurations from the database.
 * This repository supports multi-tenant environments where each tenant can have
 * their own OIDC provider configurations.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DynamicClientRegistrationRepository implements ClientRegistrationRepository {

    private final SsoConfigService ssoConfigService;

    /**
     * This method is called by Spring Security when processing OAuth2 authorization requests.
     * It loads the client configuration dynamically from the database based on the registrationId.
     *
     * The registrationId typically comes from URLs like:
     * - /oauth2/authorization/{registrationId}
     * - /login/oauth2/code/{registrationId}
     *
     * @param registrationId The unique identifier for the OIDC provider (e.g., "oidc_miniorange")
     * @return ClientRegistration if found and valid, null otherwise
     */
    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        // ✅ DEFENSIVE CHECK: Ensure tenant context exists
        Long tenantId = TenantContext.getCurrentTenant();

        if (tenantId == null) {
            log.error("❌ SECURITY ISSUE: No tenant context when looking up OIDC registration: '{}'",
                    registrationId);
            log.error("   This should never happen during normal OAuth2 flow.");
            log.error("   Possible causes: TenantFilter not applied, or direct URL access bypassing filters");
            return null;
        }

        log.debug("🔍 Loading OIDC client registration: '{}' for tenant: {}", registrationId, tenantId);

        // Load configuration from database (tenant-aware via SsoConfigService)
        SsoProviderConfig config = ssoConfigService.getConfigByProviderId(registrationId).orElse(null);

        // ✅ VALIDATION: Check if config exists
        if (config == null) {
            log.warn("⚠️ OIDC configuration not found: '{}' in tenant: {}", registrationId, tenantId);
            return null;
        }

        // ✅ VALIDATION: Check if config is enabled
        if (!config.isEnabled()) {
            log.warn("⚠️ OIDC configuration is disabled: '{}' in tenant: {}", registrationId, tenantId);
            return null;
        }

        // ✅ VALIDATION: Check if it's actually an OIDC provider
        if (config.getProviderType() != SsoProviderType.OIDC) {
            log.error("❌ Provider '{}' is type {} but OIDC was requested",
                    registrationId, config.getProviderType());
            return null;
        }

        // ✅ SECURITY: Verify tenant ownership
        if (config.getTenant() == null || !config.getTenant().getId().equals(tenantId)) {
            log.error("❌ SECURITY VIOLATION: OIDC config '{}' belongs to tenant {}, but current tenant is {}",
                    registrationId,
                    config.getTenant() != null ? config.getTenant().getId() : "NULL",
                    tenantId);
            return null;
        }

        log.info("✅ Found valid OIDC configuration: '{}' (Display: '{}') for tenant: {}",
                registrationId, config.getDisplayName(), tenantId);

        // Build the ClientRegistration dynamically
        try {
            ClientRegistration clientRegistration = buildClientRegistration(config);
            log.debug("✅ Successfully built ClientRegistration for: '{}'", registrationId);
            return clientRegistration;

        } catch (Exception e) {
            log.error("❌ Failed to build ClientRegistration for '{}': {}", registrationId, e.getMessage(), e);
            return null;
        }
    }

    /**
     * Builds a Spring Security ClientRegistration from our database configuration.
     *
     * @param config The SSO provider configuration from the database
     * @return A fully configured ClientRegistration
     */
    private ClientRegistration buildClientRegistration(SsoProviderConfig config) {
        // Validate required fields
        validateRequiredFields(config);

        // Start building the registration
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(config.getProviderId())
                .clientId(config.getClientId())
                .clientSecret(config.getClientSecret())
                .clientName(config.getDisplayName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

        // ✅ CRITICAL: Only set issuerUri if explicitly provided
        // If blank, Spring Security will use OpenID Connect Discovery
        // This is essential for providers like MiniOrange that don't require it
        if (StringUtils.hasText(config.getIssuerUri())) {
            log.debug("   Setting explicit issuerUri: {}", config.getIssuerUri());
            builder.issuerUri(config.getIssuerUri());
        } else {
            log.debug("   No issuerUri provided - Spring will use OIDC Discovery");
        }

        // Parse and add scopes
        if (StringUtils.hasText(config.getScopes())) {
            builder.scope(Arrays.stream(config.getScopes().split(","))
                    .map(String::trim)
                    .filter(StringUtils::hasText)
                    .collect(Collectors.toSet()));
        } else {
            // Default scopes if none specified
            log.debug("   No scopes configured, using defaults: openid, profile, email");
            builder.scope("openid", "profile", "email");
        }

        // Set userNameAttribute (the claim to use as the username)
        if (StringUtils.hasText(config.getUserNameAttribute())) {
            builder.userNameAttributeName(config.getUserNameAttribute());
        } else {
            // Default to 'sub' which is standard in OIDC
            builder.userNameAttributeName("sub");
        }

        // ✅ ENDPOINT OVERRIDES: Only set if provided (otherwise discovery is used)
        if (StringUtils.hasText(config.getAuthorizationUri())) {
            log.debug("   Setting explicit authorizationUri");
            builder.authorizationUri(config.getAuthorizationUri());
        }

        if (StringUtils.hasText(config.getTokenUri())) {
            log.debug("   Setting explicit tokenUri");
            builder.tokenUri(config.getTokenUri());
        }

        if (StringUtils.hasText(config.getUserInfoUri())) {
            log.debug("   Setting explicit userInfoUri");
            builder.userInfoUri(config.getUserInfoUri());
        }

        if (StringUtils.hasText(config.getJwkSetUri())) {
            log.debug("   Setting explicit jwkSetUri");
            builder.jwkSetUri(config.getJwkSetUri());
        }

        return builder.build();
    }

    /**
     * Validates that all required fields are present for OIDC configuration.
     *
     * @param config The configuration to validate
     * @throws IllegalArgumentException if required fields are missing
     */
    private void validateRequiredFields(SsoProviderConfig config) {
        if (!StringUtils.hasText(config.getProviderId())) {
            throw new IllegalArgumentException("ProviderId is required");
        }

        if (!StringUtils.hasText(config.getClientId())) {
            log.error("❌ ClientId is missing for provider: {}", config.getProviderId());
            throw new IllegalArgumentException("ClientId is required for OIDC provider: " + config.getProviderId());
        }

        if (!StringUtils.hasText(config.getClientSecret())) {
            log.error("❌ ClientSecret is missing for provider: {}", config.getProviderId());
            throw new IllegalArgumentException("ClientSecret is required for OIDC provider: " + config.getProviderId());
        }

        // Validate that at least one of these is present:
        // - issuerUri (for discovery)
        // - OR all explicit endpoints (authorizationUri, tokenUri, userInfoUri, jwkSetUri)
        boolean hasIssuer = StringUtils.hasText(config.getIssuerUri());
        boolean hasAllEndpoints = StringUtils.hasText(config.getAuthorizationUri()) &&
                StringUtils.hasText(config.getTokenUri()) &&
                StringUtils.hasText(config.getUserInfoUri()) &&
                StringUtils.hasText(config.getJwkSetUri());

        if (!hasIssuer && !hasAllEndpoints) {
            log.error("❌ Invalid OIDC configuration for '{}': Must provide either issuerUri OR all endpoints",
                    config.getProviderId());
            throw new IllegalArgumentException(
                    "OIDC provider '" + config.getProviderId() +
                            "' must have either issuerUri (for discovery) or all explicit endpoints configured");
        }

        log.debug("✅ Validation passed for OIDC provider: {}", config.getProviderId());
    }
}