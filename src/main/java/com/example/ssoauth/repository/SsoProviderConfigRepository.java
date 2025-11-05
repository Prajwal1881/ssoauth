package com.example.ssoauth.repository;

import com.example.ssoauth.entity.SsoProviderConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SsoProviderConfigRepository extends JpaRepository<SsoProviderConfig, Long> {

    // --- NEW: Method for Super-Admin stats ---
    /**
     * Finds all enabled SSO providers for a specific tenant ID.
     * This query is now explicit.
     */
    List<SsoProviderConfig> findByTenantIdAndEnabledTrue(Long tenantId);

    // --- FIX: Make all queries tenant-aware ---

    /**
     * Finds a provider config by its ID, scoped to the current tenant.
     * The @Filter should catch this, but we will also make an explicit one.
     */
    Optional<SsoProviderConfig> findByIdAndTenantId(Long id, Long tenantId);

    /**
     * Finds a provider config by its string providerId, scoped to the current tenant.
     * THIS IS THE KEY FIX.
     */
    Optional<SsoProviderConfig> findByProviderIdAndTenantId(String providerId, Long tenantId);

    /**
     * Checks for existence, scoped to the current tenant.
     */
    boolean existsByProviderIdAndTenantId(String providerId, Long tenantId);


    // --- Original Methods (now auto-filtered by Hibernate, e.g., for findAll()) ---
    // We keep these for the AdminService's manual filter logic.
    List<SsoProviderConfig> findByEnabledTrue();
    Optional<SsoProviderConfig> findByProviderId(String providerId);

}