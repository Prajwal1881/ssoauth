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
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;

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
     */
    @Transactional
    public User processOidcLogin(OidcUser oidcUser) {
        log.info("Processing OIDC Login for email: {}", oidcUser.getEmail());
        // Use OIDC 'sub' (subject) claim as the unique provider ID
        return processSsoLogin(
                oidcUser.getEmail(),
                oidcUser.getGivenName(),
                oidcUser.getFamilyName(),
                oidcUser.getSubject(),
                User.AuthProvider.OIDC,
                oidcUser.getIssuer().toString() // Pass issuer as registrationId
        );
    }

    /**
     * NEW: Handles the SAML login flow.
     */
    @Transactional
    public User processSamlLogin(Saml2AuthenticatedPrincipal samlUser) {
        String email = samlUser.getFirstAttribute("email");
        if (email == null) {
            // Fallback to NameID if email attribute isn't present
            email = samlUser.getName();
        }
        log.info("Processing SAML Login for email: {}", email);

        // Use SAML 'NameID' as the unique provider ID
        String providerId = samlUser.getName();

        // Extract registrationId (e.g., "saml_miniorange")
        String registrationId = samlUser.getRelyingPartyRegistrationId();

        return processSsoLogin(
                email,
                samlUser.getFirstAttribute("firstName"),
                samlUser.getFirstAttribute("lastName"),
                providerId,
                User.AuthProvider.SAML,
                registrationId // Pass the registrationId
        );
    }


    /**
     * Generic method to find or create an SSO user in the database.
     * UPDATED to find or create by providerId OR email.
     */
    @Transactional
    public User processSsoLogin(String email, String firstName, String lastName, String providerId, User.AuthProvider provider, String registrationId) {
        if (email == null || email.isEmpty()) {
            log.error("Email from SSO provider ({}) is null or empty. Cannot process login.", provider);
            throw new IllegalArgumentException("Email from SSO provider cannot be null");
        }
        log.info("Processing SSO login for email: {}, provider: {}, providerId: {}", email, provider, providerId);

        // Try to find user by their unique providerId first
        User user = userRepository.findByProviderId(providerId)
                .or(() -> {
                    // If not found by providerId, try by email
                    log.warn("User not found by providerId {}. Attempting lookup by email: {}", providerId, email);
                    return userRepository.findByEmail(email); // Uses cache-bypassing query
                })
                .map(existingUser -> {
                    // User exists, update details if necessary
                    log.info("Found existing user by email or providerId: {}. Updating details.", email);
                    existingUser.setAuthProvider(provider);
                    existingUser.setProviderId(providerId); // Ensure providerId is set
                    existingUser.setLastLogin(LocalDateTime.now());
                    return userRepository.save(existingUser);
                })
                .orElseGet(() -> {
                    // User does not exist, create a new one
                    log.info("Creating new SSO user via {} for email: {}", provider, email);

                    // Use registrationId (e.g., saml_miniorange) to generate a unique username
                    String username = generateUniqueUsername(email, registrationId);

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
                    newUser.setLastLogin(LocalDateTime.now());
                    return userRepository.save(newUser);
                });

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
    private String generateUniqueUsername(String email, String registrationId) {
        // Clean up registrationId to be a valid username part
        String cleanRegId = registrationId.replaceAll("[^a-zA-Z0-9_]", "_");

        String baseUsername = email.split("@")[0].replaceAll("[^a-zA-Z0-9]", "_") + "_" + cleanRegId;

        // Ensure username is not too long
        if (baseUsername.length() > 40) {
            baseUsername = baseUsername.substring(0, 40);
        }

        if (!userRepository.existsByUsername(baseUsername)) {
            return baseUsername;
        }

        // If base exists, add counter
        String finalUsername = baseUsername;
        int counter = 1;
        while (userRepository.existsByUsername(finalUsername)) {
            finalUsername = baseUsername + "_" + counter++;
            if (finalUsername.length() > 50) { // Max username length
                finalUsername = baseUsername.substring(0, 40) + "_" + counter++;
            }
        }
        return finalUsername;
    }
}