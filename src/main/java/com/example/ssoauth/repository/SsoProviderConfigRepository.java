package com.example.ssoauth.repository;

import com.example.ssoauth.entity.SsoProviderConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List; // NEW IMPORT
import java.util.Optional;

@Repository
public interface SsoProviderConfigRepository extends JpaRepository<SsoProviderConfig, Long> {

    // --- NEW: Method for Super-Admin stats ---
    /**
     * Finds all enabled SSO providers for a specific tenant ID.
     * This query is explicit and does not rely on the Hibernate filter.
     */
    List<SsoProviderConfig> findByTenantIdAndEnabledTrue(Long tenantId);

    // --- Original Methods (now auto-filtered by Hibernate) ---

    List<SsoProviderConfig> findByEnabledTrue();

    Optional<SsoProviderConfig> findByProviderId(String providerId);

    boolean existsByProviderId(String providerId);
}