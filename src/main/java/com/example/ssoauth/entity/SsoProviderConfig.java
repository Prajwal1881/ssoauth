package com.example.ssoauth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "sso_provider_configs")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SsoProviderConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String providerId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private SsoProviderType providerType;

    @Column(nullable = false, length = 100)
    private String displayName;

    @Column(nullable = false)
    private boolean enabled;

    // --- Common Fields ---
    @Column(length = 512)
    private String issuerUri;

    @Column(length = 255)
    private String clientId;

    @Column(length = 512)
    private String clientSecret;

    @Column(length = 512)
    private String scopes;

    // --- OIDC Specific Fields ---
    @Column(length = 512)
    private String authorizationUri;

    @Column(length = 512)
    private String tokenUri;

    @Column(length = 512)
    private String userInfoUri;

    @Column(length = 512)
    private String jwkSetUri;

    @Column(length = 100)
    private String userNameAttribute;

    // --- Manual JWT Specific Fields ---
    @Column(length = 512)
    private String jwtSsoUrl;

    @Column(length = 512)
    private String jwtRedirectUri;

    @Column(columnDefinition = "TEXT")
    private String jwtCertificate;

    // --- SAML Specific Fields ---
    @Column(length = 512)
    private String samlSsoUrl;

    @Column(length = 512)
    private String samlEntityId;

    @Column(columnDefinition = "TEXT")
    private String samlCertificate;


    // --- Attribute Mapping Fields ---
    // (We are removing all 'attribute_...' fields)


    // --- Timestamps ---
    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;
}