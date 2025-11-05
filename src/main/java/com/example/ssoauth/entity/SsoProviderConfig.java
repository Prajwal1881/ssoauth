package com.example.ssoauth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.Filter;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "sso_provider_configs", uniqueConstraints = {
        // --- FIX ---
        // Changed "provider_id" to "providerId" to match the
        // entity's property name, which is also the database column name.
        @UniqueConstraint(columnNames = {"tenant_id", "providerId"})
        // --- End Fix ---
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
public class SsoProviderConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(nullable = false, length = 100)
    private String providerId; // This property maps to the "providerId" column

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

    // --- Timestamps ---
    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;
}