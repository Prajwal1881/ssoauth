package com.example.ssoauth.repository;

import com.example.ssoauth.entity.SsoProviderConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SsoProviderConfigRepository extends JpaRepository<SsoProviderConfig, Long> {

    // --- PRIMARY TENANT-AWARE QUERIES (Use these for all tenant-scoped operations) ---

    /**
     * CRITICAL: Find config by ID and tenant ID (prevents cross-tenant access).
     */
    @Query("SELECT s FROM SsoProviderConfig s WHERE s.id = :id AND s.tenant.id = :tenantId")
    Optional<SsoProviderConfig> findByIdAndTenantId(@Param("id") Long id, @Param("tenantId") Long tenantId);

    /**
     * CRITICAL: Find config by provider ID and tenant ID.
     */
    @Query("SELECT s FROM SsoProviderConfig s WHERE s.providerId = :providerId AND s.tenant.id = :tenantId")
    Optional<SsoProviderConfig> findByProviderIdAndTenantId(@Param("providerId") String providerId, @Param("tenantId") Long tenantId);

    /**
     * Find all enabled providers for a specific tenant.
     */
    @Query("SELECT s FROM SsoProviderConfig s WHERE s.tenant.id = :tenantId AND s.enabled = true")
    List<SsoProviderConfig> findByTenantIdAndEnabledTrue(@Param("tenantId") Long tenantId);

    /**
     * Check if provider ID exists within a specific tenant.
     */
    @Query("SELECT CASE WHEN COUNT(s) > 0 THEN true ELSE false END FROM SsoProviderConfig s WHERE s.providerId = :providerId AND s.tenant.id = :tenantId")
    boolean existsByProviderIdAndTenantId(@Param("providerId") String providerId, @Param("tenantId") Long tenantId);

    // --- DEBUG QUERY (Use for troubleshooting) ---

    /**
     * DEBUG: Get all configs with tenant info (for troubleshooting only).
     * DO NOT use this in production code paths.
     */
    @Query("SELECT s.id, s.providerId, s.providerType, s.tenant.id, s.tenant.subdomain FROM SsoProviderConfig s")
    List<Object[]> findAllWithTenantInfo();

    // --- LEGACY QUERIES (These rely on Hibernate filter - avoid if possible) ---

    /**
     * CAUTION: This query relies on Hibernate filter being enabled.
     * Prefer explicit tenant-aware queries above.
     */
    List<SsoProviderConfig> findByEnabledTrue();

    /**
     * CAUTION: This query relies on Hibernate filter being enabled.
     * Prefer findByProviderIdAndTenantId() instead.
     */
    Optional<SsoProviderConfig> findByProviderId(String providerId);
}