package com.example.ssoauth.dto;

import com.example.ssoauth.entity.SsoProviderType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class SsoProviderConfigUpdateRequest {

    @NotBlank
    private String providerId;

    @NotNull
    private SsoProviderType providerType;

    @NotBlank
    private String displayName;

    @NotNull
    private Boolean enabled;

    // Common
    private String issuerUri;
    private String clientId;
    private String clientSecret;
    private String scopes;

    // OIDC
    private String authorizationUri;
    private String tokenUri;
    private String userInfoUri;
    private String jwkSetUri;
    private String userNameAttribute;

    // JWT
    private String jwtSsoUrl;
    private String jwtRedirectUri;
    private String jwtCertificate;

    // SAML
    private String samlSsoUrl;
    private String samlEntityId;
    private String samlCertificate;

    // --- Attribute Mapping Fields ---
    // (We are removing all 'attribute...' fields)
}