package com.example.ssoauth.dto;

import com.example.ssoauth.entity.SsoProviderType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SsoProviderConfigDto {
    private Long id;
    private String providerId;
    private SsoProviderType providerType;
    private String displayName;
    private boolean enabled;

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