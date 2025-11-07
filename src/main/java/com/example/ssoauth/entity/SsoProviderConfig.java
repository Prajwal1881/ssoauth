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
        @UniqueConstraint(columnNames = {"tenant_id", "providerId"})
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

    // ========================================
    // NEW: KERBEROS SPECIFIC FIELDS
    // ========================================

    /**
     * Kerberos Service Principal Name (SPN)
     * Example: HTTP/yourapp.yourdomain.com@YOURDOMAIN.COM
     */
    @Column(length = 255)
    private String kerberosServicePrincipal;

    /**
     * Keytab file content (Base64 encoded)
     * The keytab contains the service principal's credentials
     */
    @Column(columnDefinition = "TEXT")
    private String kerberosKeytabBase64;

    /**
     * Kerberos Realm (Active Directory Domain)
     * Example: YOURDOMAIN.COM
     */
    @Column(length = 100)
    private String kerberosRealm;

    /**
     * KDC (Key Distribution Center) Server Address
     * Example: dc.yourdomain.com
     */
    @Column(length = 255)
    private String kerberosKdcServer;

    /**
     * User attribute to extract from Kerberos principal
     * Options: "username" (extract before @), "email" (full principal), "upn"
     */
    @Column(length = 50)
    private String kerberosUserNameAttribute;

    // --- Timestamps ---
    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;
}