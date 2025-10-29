package com.example.ssoauth.dto;

import com.example.ssoauth.entity.SsoProviderType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

// DTO for returning config details (exclude sensitive info like secret if needed)
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
    // Exclude clientSecret by default for GET requests
    private String scopes;

    // OIDC
    private String authorizationUri;
    private String tokenUri;
    private String userInfoUri;
    private String jwkSetUri;
    private String userNameAttribute;

    // JWT
    private String jwtSsoUrl;
    private String jwtCertificate; // Or maybe just indicate if present

    // SAML
    private String samlSsoUrl;
    private String samlEntityId;
    private String samlCertificate; // Or maybe just indicate if present

    // Add createdAt, updatedAt if needed
}