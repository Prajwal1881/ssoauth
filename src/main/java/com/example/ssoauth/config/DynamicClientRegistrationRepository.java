package com.example.ssoauth.config;

import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.entity.SsoProviderType;
import com.example.ssoauth.service.SsoConfigService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils; // NEW IMPORT

import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * Dynamically loads OIDC (OAuth2) client configurations from the database.
 */
@Component
@RequiredArgsConstructor
public class DynamicClientRegistrationRepository implements ClientRegistrationRepository {

    private final SsoConfigService ssoConfigService;

    /**
     * This method is called by Spring Security (e.g., when /oauth2/authorization/{regId} is hit).
     * It uses the {regId} to look up the configuration in our database.
     */
    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        SsoProviderConfig config = ssoConfigService.getConfigByProviderId(registrationId).orElse(null);

        if (config == null || !config.isEnabled() || config.getProviderType() != SsoProviderType.OIDC) {
            // If not found, not enabled, or not OIDC, return null.
            return null;
        }

        // --- THIS IS THE FIX ---
        // We will now build the registration dynamically
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(config.getProviderId())
                .clientId(config.getClientId())
                .clientSecret(config.getClientSecret())
                .clientName(config.getDisplayName())
                .authorizationUri(config.getAuthorizationUri())
                .tokenUri(config.getTokenUri())
                .userInfoUri(config.getUserInfoUri())
                .jwkSetUri(config.getJwkSetUri())
                .userNameAttributeName(config.getUserNameAttribute())
                .authorizationGrantType(new AuthorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()))
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope(Arrays.stream(config.getScopes().split(","))
                        .map(String::trim)
                        .collect(Collectors.toSet()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);

        // *** THIS IS THE CRITICAL CHANGE ***
        // Only set the Issuer URI if the user has provided one.
        // If it's blank, we let Spring Security discover it automatically
        // (which is the correct behavior for your MiniOrange setup).
        if (StringUtils.hasText(config.getIssuerUri())) {
            builder.issuerUri(config.getIssuerUri());
        }

        return builder.build();
    }
}