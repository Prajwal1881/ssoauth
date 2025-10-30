package com.example.ssoauth.dto;

import com.example.ssoauth.entity.SsoProviderType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

// DTO for updating configurations via API
@Data
public class SsoProviderConfigUpdateRequest {

    @NotBlank
    private String providerId; // Usually not updatable, but needed for lookup/validation

    @NotNull
    private SsoProviderType providerType; // Usually not updatable

    @NotBlank
    private String displayName;

    @NotNull
    private Boolean enabled;

    // Include all fields that can be updated from the admin UI
    // Make them nullable/optional as needed
    private String issuerUri;
    private String clientId;
    private String clientSecret; // Allow updating the secret
    private String scopes;

    // OIDC
    private String authorizationUri;
    private String tokenUri;
    private String userInfoUri;
    private String jwkSetUri;
    private String userNameAttribute;

    // JWT
    private String jwtSsoUrl;
    private String jwtRedirectUri; // *** NEW FIELD ADDED ***
    private String jwtCertificate;

    // SAML
    private String samlSsoUrl;
    private String samlEntityId;
    private String samlCertificate;
}