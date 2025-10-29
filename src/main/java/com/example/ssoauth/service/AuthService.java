package com.example.ssoauth.service;

import com.example.ssoauth.dto.*;
import com.example.ssoauth.entity.User;
import com.example.ssoauth.exception.ResourceAlreadyExistsException;
import com.example.ssoauth.repository.UserRepository;
import com.example.ssoauth.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * Handles local username/password sign-in.
     */
    @Transactional
    public JwtAuthResponse signIn(SignInRequest signInRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        signInRequest.getUsernameOrEmail(),
                        signInRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String username = authentication.getName();
        User user = userRepository.findByUsernameOrEmail(username, username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));

        userRepository.updateLastLogin(user.getId(), LocalDateTime.now());

        String accessToken = jwtTokenProvider.generateToken(authentication);
        String refreshToken = jwtTokenProvider.generateRefreshToken(username);

        return JwtAuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getJwtExpirationMs())
                .userInfo(mapToUserInfo(user))
                .build();
    }

    /**
     * Handles local user sign-up.
     */
    @Transactional
    public JwtAuthResponse signUp(SignUpRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            throw new ResourceAlreadyExistsException("Username is already taken!");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new ResourceAlreadyExistsException("Email is already in use!");
        }

        User user = User.builder()
                .username(signUpRequest.getUsername())
                .email(signUpRequest.getEmail())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .firstName(signUpRequest.getFirstName())
                .lastName(signUpRequest.getLastName())
                .authProvider(User.AuthProvider.LOCAL)
                .roles("ROLE_USER")
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();

        User savedUser = userRepository.save(user);

        // Authenticate the user immediately after sign-up
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        signUpRequest.getUsername(),
                        signUpRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accessToken = jwtTokenProvider.generateToken(authentication);
        String refreshToken = jwtTokenProvider.generateRefreshToken(savedUser.getUsername());

        return JwtAuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getJwtExpirationMs())
                .userInfo(mapToUserInfo(savedUser))
                .build();
    }

    /**
     * Handles the OIDC login flow.
     * Extracts info from the OidcUser and calls the generic processSsoLogin method.
     */
    @Transactional
    public User processOidcLogin(OidcUser oidcUser) {
        log.info("Processing OIDC Login for email: {}", oidcUser.getEmail());
        return processSsoLogin(
                oidcUser.getEmail(),
                oidcUser.getGivenName(),
                oidcUser.getFamilyName(),
                oidcUser.getSubject(),
                User.AuthProvider.SSO
        );
    }

    /**
     * Generic method to find or create an SSO user in the database.
     * UPDATED: Uses cache-bypassing query to ensure roles are current.
     */
    @Transactional
    public User processSsoLogin(String email, String firstName, String lastName, String providerId, User.AuthProvider provider) {
        if (email == null || email.isEmpty()) {
            log.error("Email from SSO provider ({}) is null or empty. Cannot process login.", provider);
            throw new IllegalArgumentException("Email from SSO provider cannot be null");
        }
        log.info("Processing SSO login for email: {}, provider: {}", email, provider);

        // !!! CRITICAL FIX: Use the cache-bypassing query here !!!
        User user = userRepository.findByEmail(email)
                .map(existingUser -> {
                    // User exists, update last login time and return
                    log.info("Found existing user by email: {}. Updating last login.", email);
                    // The returned entity has the FRESH roles loaded directly from DB.
                    if (provider == User.AuthProvider.SSO_JWT) {
                        // This ensures the entity is marked as having the Admin role for the current transaction
                        existingUser.addRole("ROLE_ADMIN");
                        log.info("Forced ROLE_ADMIN onto entity for redirection check.");
                    }
                    return existingUser;
                })
                .orElseGet(() -> {
                    // User does not exist, create a new one
                    log.info("Creating new SSO user via {} for email: {}", provider, email);
                    String username = generateUniqueUsername(email, provider, providerId);

                    User newUser = User.builder()
                            .username(username)
                            .email(email)
                            .password(passwordEncoder.encode(generateRandomPassword())) // Unusable password
                            .firstName(firstName)
                            .lastName(lastName)
                            .authProvider(provider)
                            .providerId(providerId)
                            .roles("ROLE_USER") // New SSO users get default role
                            .enabled(true)
                            .accountNonExpired(true)
                            .accountNonLocked(true)
                            .credentialsNonExpired(true)
                            .build();
                    return userRepository.save(newUser);
                });

        userRepository.updateLastLogin(user.getId(), LocalDateTime.now());
        log.info("Updated last login for user ID: {}", user.getId());
        return user;
    }


    private String generateRandomPassword() {
        return java.util.UUID.randomUUID().toString();
    }

    private UserInfo mapToUserInfo(User user) {
        return UserInfo.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .authProvider(user.getAuthProvider().name())
                .roles(user.getRoles())
                .build();
    }

    // Helper to generate a potentially unique username
    private String generateUniqueUsername(String email, User.AuthProvider provider, String providerId) {
        String baseUsername = email.split("@")[0] + "_" + provider.name().toLowerCase();
        if (!userRepository.existsByUsername(baseUsername)) {
            return baseUsername;
        }
        // If base exists, add part of the providerId hash for uniqueness
        String uniqueSuffix = Integer.toHexString(providerId.hashCode()).substring(0, Math.min(6, Integer.toHexString(providerId.hashCode()).length()));
        String finalUsername = baseUsername + "_" + uniqueSuffix;

        // Final check in case of hash collision (rare)
        int counter = 1;
        while (userRepository.existsByUsername(finalUsername)) {
            finalUsername = baseUsername + "_" + uniqueSuffix + "_" + counter++;
        }
        return finalUsername;
    }
}