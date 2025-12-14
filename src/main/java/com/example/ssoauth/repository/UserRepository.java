package com.example.ssoauth.repository;

import com.example.ssoauth.entity.Tenant; // NEW IMPORT
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

    Optional<User> findByUsernameAndTenantId(String username, Long tenantId);

    // --- NEW: Method for Super-Admin stats ---
    /**
     * Counts all users associated with a specific tenant.
     */
    Long countByTenant(Tenant tenant);

    // --- Tenant-Aware Methods (Corrected from previous steps) ---

    Optional<User> findByTenantIdAndUsernameOrTenantIdAndEmail(Long tenantId1, String username, Long tenantId2, String email);

    @Query("SELECT u FROM User u WHERE (u.username = :username OR u.email = :email) AND u.tenant IS NULL")
    Optional<User> findByUsernameOrEmailAndTenantIsNull(@Param("username") String username, @Param("email") String email);

    Boolean existsByUsernameAndTenantId(String username, Long tenantId);
    Boolean existsByEmailAndTenantId(String email, Long tenantId);
    Boolean existsByUsernameAndTenantIdIsNull(String username);
    Boolean existsByEmailAndTenantIdIsNull(String email);
    Optional<User> findByEmailAndTenantId(String email, Long tenantId);

    // --- Original Methods (now auto-filtered by Hibernate) ---

    @QueryHints(@QueryHint(name = "jakarta.persistence.cache.retrieveMode", value = "BYPASS"))
    Optional<User> findByEmail(String email);

    Optional<User> findByProviderId(String providerId);
    List<User> findByAuthProvider(User.AuthProvider authProvider);
    List<User> findByEnabledTrue();
    List<User> findByEnabledFalse();

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

    // --- FIX: Removed "Some(" and ")" wrapper ---
    Long countByAuthProvider(User.AuthProvider authProvider);
    Long countByEnabledTrue();
    // --- End Fix ---

    List<User> findByCreatedAtAfter(LocalDateTime date);
    List<User> findByLastLoginAfter(LocalDateTime date);

    @Transactional
    void deleteByUsername(String username);
    @Transactional
    void deleteByEmail(String email);

    List<User> findByUsernameContainingIgnoreCase(String username);
    List<User> findByEmailContainingIgnoreCase(String email);
    List<User> findByFirstNameContainingIgnoreCaseOrLastNameContainingIgnoreCase(
            String firstName, String lastName);
}