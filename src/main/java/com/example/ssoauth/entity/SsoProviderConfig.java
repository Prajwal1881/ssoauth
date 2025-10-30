package com.example.ssoauth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

/**
 * Entity representing the configuration for an external SSO provider.
 * Stores details for OIDC, Manual JWT, or SAML protocols.
 */
@Entity
@Table(name = "sso_provider_configs") // Maps to the database table
@Data // Lombok annotation for getters, setters, toString, equals, hashCode
@NoArgsConstructor // Lombok annotation for no-args constructor
@AllArgsConstructor // Lombok annotation for all-args constructor
@Builder // Lombok annotation for builder pattern
public class SsoProviderConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id; // Primary key

    @Column(nullable = false, unique = true, length = 100)
    private String providerId; // Unique identifier (e.g., 'oidc_miniorange', 'jwt_google')

    @Enumerated(EnumType.STRING) // Store enum names (OIDC, JWT, SAML) as strings
    @Column(nullable = false, length = 20)
    private SsoProviderType providerType; // Type of SSO protocol

    @Column(nullable = false, length = 100)
    private String displayName; // User-friendly name for the provider

    @Column(nullable = false)
    private boolean enabled; // Toggle to enable/disable this provider

    // --- Common Fields (used by multiple protocols) ---
    @Column(length = 512)
    private String issuerUri; // Issuer identifier (iss claim or entity ID)

    @Column(length = 255)
    private String clientId; // Client ID provided by the IdP

    @Column(length = 512) // Increased length for potentially long secrets
    private String clientSecret; // Client Secret provided by the IdP (consider encryption)

    @Column(length = 512)
    private String scopes; // Requested scopes (e.g., "openid, profile, email"), comma-separated

    // --- OIDC Specific Fields ---
    @Column(length = 512)
    private String authorizationUri; // OIDC Authorization Endpoint URL

    @Column(length = 512)
    private String tokenUri; // OIDC Token Endpoint URL

    @Column(length = 512)
    private String userInfoUri; // OIDC UserInfo Endpoint URL

    @Column(length = 512)
    private String jwkSetUri; // OIDC JWK Set URL for token signature verification

    @Column(length = 100)
    private String userNameAttribute; // Claim to use as the principal name (e.g., 'email', 'sub')

    // --- Manual JWT Specific Fields ---
    @Column(length = 512)
    private String jwtSsoUrl; // URL to redirect the user to for initiating JWT SSO

    // *** NEW FIELD ADDED ***
    @Column(length = 512)
    private String jwtRedirectUri; // Callback URL for JWT flow

    // Use TEXT type for potentially long certificate strings in PostgreSQL
    @Column(columnDefinition = "TEXT")
    private String jwtCertificate; // Public certificate (PEM format) for JWT signature verification

    // --- SAML Specific Fields ---
    @Column(length = 512)
    private String samlSsoUrl; // SAML SingleSignOnService URL (POST or Redirect binding)

    @Column(length = 512)
    private String samlEntityId; // SAML Identity Provider Entity ID (often same as issuerUri)

    // Use TEXT type for potentially long certificate strings in PostgreSQL
    @Column(columnDefinition = "TEXT")
    private String samlCertificate; // SAML public signing certificate (PEM format)

    // --- Timestamps ---
    @CreationTimestamp // Automatically set on creation
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp // Automatically set on update
    private LocalDateTime updatedAt;
}