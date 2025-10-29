package com.example.ssoauth.controller;

import com.example.ssoauth.dto.UserInfo;
import com.example.ssoauth.entity.User;
import com.example.ssoauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j; // Import Slf4j
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
@Slf4j // Add logger
public class UserController {

    private final UserRepository userRepository;

    /**
     * Retrieves details for the currently authenticated user.
     * UPDATED: Uses findByEmail to ensure fresh roles are loaded (assuming email is reliable here).
     */
    @GetMapping("/me")
    public ResponseEntity<UserInfo> getCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("Attempt to access /api/user/me without authentication.");
            return ResponseEntity.status(401).build(); // Explicitly return 401
        }

        String usernameOrEmail = authentication.getName(); // This is usually the username from UserDetails
        log.info("Fetching current user details for principal: {}", usernameOrEmail);

        // !!! FIX: Load user bypassing cache to get fresh roles !!!
        // We assume the principal name (username) might be different from email,
        // so we first get the user, then use their email for the fresh load.
        // If username and email are always the same, you could simplify this.
        User potentiallyStaleUser = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with principal: " + usernameOrEmail));

        // Now load fresh data using the email
        User freshUser = userRepository.findByEmail(potentiallyStaleUser.getEmail()) // Uses the cache-bypassing findByEmail
                .orElseThrow(() -> new UsernameNotFoundException("Fresh user data not found for email: " + potentiallyStaleUser.getEmail()));

        log.info("Successfully loaded fresh user data for ID: {}. Roles: '{}'", freshUser.getId(), freshUser.getRoles());

        // Map the FRESH user data to the DTO
        UserInfo userInfo = UserInfo.builder()
                .id(freshUser.getId())
                .username(freshUser.getUsername())
                .email(freshUser.getEmail())
                .firstName(freshUser.getFirstName())
                .lastName(freshUser.getLastName())
                .authProvider(freshUser.getAuthProvider().name())
                .roles(freshUser.getRoles()) // Use roles from the fresh entity
                .build();

        log.info("Returning UserInfo for /api/user/me with roles: '{}'", userInfo.getRoles());
        return ResponseEntity.ok(userInfo);
    }
}