package com.example.ssoauth.repository;

import com.example.ssoauth.entity.Tenant;
import com.example.ssoauth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.QueryHint;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // --- Tenant-Aware Lookups ---

    /**
     * CRITICAL FIX: Find by Provider ID strictly within the current Tenant.
     * Prevents cross-tenant login issues (e.g., finding user in Tenant 21 when logging into Tenant 13).
     */
    Optional<User> findByProviderIdAndTenantId(String providerId, Long tenantId);

    /**
     * CRITICAL FIX: Case-insensitive username lookup within tenant.
     */
    Optional<User> findByUsernameIgnoreCaseAndTenantId(String username, Long tenantId);

    Optional<User> findByTenantIdAndUsernameOrTenantIdAndEmail(Long tenantId1, String username, Long tenantId2, String email);

    @Query("SELECT u FROM User u WHERE (u.username = :username OR u.email = :email) AND u.tenant IS NULL")
    Optional<User> findByUsernameOrEmailAndTenantIsNull(@Param("username") String username, @Param("email") String email);

    Optional<User> findByEmailAndTenantId(String email, Long tenantId);

    // --- Boolean Checks ---
    Boolean existsByUsernameAndTenantId(String username, Long tenantId);
    Boolean existsByEmailAndTenantId(String email, Long tenantId);
    Boolean existsByUsernameAndTenantIdIsNull(String username);
    Boolean existsByEmailAndTenantIdIsNull(String email);

    // --- Stats ---
    Long countByTenant(Tenant tenant);
    Long countByAuthProvider(User.AuthProvider authProvider);
    Long countByEnabledTrue();

    // --- Legacy / Unfiltered (Be careful using these) ---
    @QueryHints(@QueryHint(name = "jakarta.persistence.cache.retrieveMode", value = "BYPASS"))
    Optional<User> findByEmail(String email);

    List<User> findByAuthProvider(User.AuthProvider authProvider);
    List<User> findByEnabledTrue();
    List<User> findByEnabledFalse();

    // --- Updates ---
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.lastLogin = :lastLogin WHERE u.id = :userId")
    void updateLastLogin(@Param("userId") Long userId, @Param("lastLogin") LocalDateTime lastLogin);

    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.enabled = :enabled WHERE u.id = :userId")
    void updateEnabledStatus(@Param("userId") Long userId, @Param("enabled") Boolean enabled);

    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.accountNonLocked = :locked WHERE u.id = :userId")
    void updateAccountLockStatus(@Param("userId") Long userId, @Param("locked") Boolean locked);

    // --- Search ---
    List<User> findByCreatedAtAfter(LocalDateTime date);
    List<User> findByLastLoginAfter(LocalDateTime date);
    List<User> findByUsernameContainingIgnoreCase(String username);
    List<User> findByEmailContainingIgnoreCase(String email);
    List<User> findByFirstNameContainingIgnoreCaseOrLastNameContainingIgnoreCase(String firstName, String lastName);

    @Transactional
    void deleteByUsername(String username);
    @Transactional
    void deleteByEmail(String email);
}