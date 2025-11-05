package com.example.ssoauth.controller;

import com.example.ssoauth.config.TenantContext;
import com.example.ssoauth.dto.UserInfo;
import com.example.ssoauth.entity.User;
import com.example.ssoauth.repository.TenantRepository; // NEW IMPORT
import com.example.ssoauth.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException; // NEW IMPORT
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserRepository userRepository;
    private final TenantRepository tenantRepository; // NEW IMPORT

    @GetMapping("/me")
    public ResponseEntity<UserInfo> getCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("Attempt to access /api/user/me without authentication.");
            return ResponseEntity.status(401).build();
        }

        String username = authentication.getName();
        log.info("Fetching current user details for principal: {}", username);

        // --- FIX: Get String subdomain and convert to Long ID ---
        String subdomain = TenantContext.getCurrentTenant();
        Optional<User> userOpt;

        if (subdomain != null) {
            // 1. Find the tenant ID from the subdomain
            Long tenantId = tenantRepository.findBySubdomain(subdomain)
                    .orElseThrow(() -> new EntityNotFoundException("Invalid tenant: " + subdomain))
                    .getId();
            // 2. Use the Long ID to find the user
            userOpt = userRepository.findByTenantIdAndUsernameOrTenantIdAndEmail(tenantId, username, tenantId, username);
        } else {
            // This is a Super Admin
            userOpt = userRepository.findByUsernameOrEmailAndTenantIsNull(username, username);
        }
        // --- END FIX ---

        User user = userOpt.orElseThrow(() -> new UsernameNotFoundException("User not found with principal: " + username));

        log.info("Successfully loaded fresh user data for ID: {}. Roles: '{}'", user.getId(), user.getRoles());

        UserInfo userInfo = UserInfo.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .authProvider(user.getAuthProvider().name())
                .roles(user.getRoles())
                .build();

        log.info("Returning UserInfo for /api/user/me with roles: '{}'", userInfo.getRoles());
        return ResponseEntity.ok(userInfo);
    }
}