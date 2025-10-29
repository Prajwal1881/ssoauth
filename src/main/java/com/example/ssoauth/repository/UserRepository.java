package com.example.ssoauth.repository;

import com.example.ssoauth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints; // NEW IMPORT
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.QueryHint; // NEW IMPORT
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    // !!! ORIGINAL findByEmail IS REMOVED/OVERRIDDEN BY THE ANNOTATED VERSION BELOW !!!
    // Optional<User> findByEmail(String email);

    Optional<User> findByUsernameOrEmail(String username, String email);

    /**
     * Finds user by email, explicitly bypassing the JPA cache to ensure fresh data from DB.
     * This method now effectively replaces the standard findByEmail for this repository.
     */
    @QueryHints(@QueryHint(name = "jakarta.persistence.cache.retrieveMode", value = "BYPASS"))
    Optional<User> findByEmail(String email); // !!! RENAMED to findByEmail !!!

    // ... (rest of the interface remains the same)


    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);

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

    Long countByAuthProvider(User.AuthProvider authProvider);

    Long countByEnabledTrue();

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