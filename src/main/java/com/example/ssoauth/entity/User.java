package com.example.ssoauth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;


@Entity
@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(columnNames = "email"),
        @UniqueConstraint(columnNames = "username")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 50)
    private String username;

    @Column(nullable = false, unique = true, length = 100)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(name = "first_name", length = 50)
    private String firstName;

    @Column(name = "last_name", length = 50)
    private String lastName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private AuthProvider authProvider = AuthProvider.LOCAL;

    @Column(name = "provider_id")
    private String providerId;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @Column(nullable = false)
    @Builder.Default
    private boolean accountNonExpired = true;

    @Column(nullable = false)
    @Builder.Default
    private boolean accountNonLocked = true;

    @Column(nullable = false)
    @Builder.Default
    private boolean credentialsNonExpired = true;

    // Added roles field
    @Column(nullable = false)
    @Builder.Default
    private String roles = "ROLE_USER"; // Default role

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    // Helper method to get roles as Spring Security Authorities
    @Transient // Mark this so JPA doesn't try to persist it
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Arrays.stream(this.roles.split(","))
                .map(String::trim) // Remove whitespace
                .filter(role -> !role.isEmpty()) // Ensure no empty roles
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    }

    // Helper to add a role
    public void addRole(String role) {
        Set<String> currentRoles = new HashSet<>(Arrays.asList(this.roles.split(",")));
        currentRoles.add(role.trim());
        this.roles = String.join(",", currentRoles);
    }

    // Helper to check if user has a role
    public boolean hasRole(String role) {
        return Arrays.asList(this.roles.split(",")).contains(role.trim());
    }

    // *** UPDATED ENUM ***
    public enum AuthProvider {
        LOCAL,
        OIDC, // Standard OIDC flow
        SAML, // Standard SAML flow
        SSO_JWT // Manual JWT Flow
    }
}