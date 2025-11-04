package com.example.ssoauth.service;

import com.example.ssoauth.dto.*;
import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.entity.User;
import com.example.ssoauth.exception.ResourceAlreadyExistsException;
import com.example.ssoauth.exception.SSOAuthenticationException;
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
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
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
    private final SsoConfigService ssoConfigService;

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
     * UPDATED: Handles the OIDC login flow using "smart" attribute finding
     */
    @Transactional
    public User processOidcLogin(OidcUser oidcUser) {
        String registrationId = oidcUser.getIssuer().toString();

        SsoProviderConfig config = ssoConfigService.getConfigByProviderId(registrationId)
                .orElseGet(() -> {
                    if (oidcUser.getIssuer().toString().startsWith("httpss://csumairkhan.xecurify.com")) {
                        return ssoConfigService.getConfigByProviderId("oidc_miniorange")
                                .orElseThrow(() -> new SSOAuthenticationException("No OIDC config found for 'oidc_miniorange'"));
                    }
                    throw new SSOAuthenticationException("No OIDC config found for issuer: " + registrationId);
                });

        Map<String, Object> claims = oidcUser.getClaims();

        // --- NEW: LOG ALL OIDC ATTRIBUTES ---
        log.info("--- OIDC ATTRIBUTE DUMP (START) ---");
        log.info("Provider: {}", config.getProviderId());
        claims.forEach((key, value) -> log.info("  Claim: '{}', Value: '{}'", key, value.toString()));
        log.info("--- OIDC ATTRIBUTE DUMP (END) ---");

        // --- "SMART" ATTRIBUTE FINDING ---
        String username = findOidcAttribute(claims, "preferred_username", "username", "uid");
        String email = findOidcAttribute(claims, "email", "mail", "userPrincipalName");
        String firstName = findOidcAttribute(claims, "given_name", "firstName", "fn");
        String lastName = findOidcAttribute(claims, "family_name", "lastName", "sn");

        if (email == null) email = oidcUser.getEmail(); // Fallback

        log.info("Processing OIDC Login for email: {}", email);

        return processSsoLogin(
                username,
                email,
                firstName,
                lastName,
                oidcUser.getSubject(),
                User.AuthProvider.OIDC,
                config.getProviderId()
        );
    }

    /**
     * UPDATED: Handles the SAML login flow using "smart" attribute finding
     */
    @Transactional
    public User processSamlLogin(Saml2AuthenticatedPrincipal samlUser) {
        String registrationId = samlUser.getRelyingPartyRegistrationId();

        SsoProviderConfig config = ssoConfigService.getConfigByProviderId(registrationId)
                .orElseThrow(() -> new SSOAuthenticationException("No SAML config found for: " + registrationId));

        Map<String, List<Object>> attributes = samlUser.getAttributes();

        // --- NEW: LOG ALL SAML ATTRIBUTES ---
        log.info("--- SAML ATTRIBUTE DUMP (START) ---");
        log.info("Provider: {}", config.getProviderId());
        attributes.forEach((key, value) -> log.info("  Attribute: '{}', Value: '{}'", key,
                value.stream().map(Object::toString).collect(Collectors.joining(","))
        ));
        log.info("--- SAML ATTRIBUTE DUMP (END) ---");

        // --- "SMART" ATTRIBUTE FINDING ---
        String username = findSamlAttribute(attributes, "username", "uid", "preferred_username");
        String email = findSamlAttribute(attributes, "email", "mail", "userPrincipalName");
        String firstName = findSamlAttribute(attributes, "firstName", "givenName", "fn");
        String lastName = findSamlAttribute(attributes, "lastName", "sn");

        if (email == null) email = samlUser.getName(); // Fallback

        log.info("Processing SAML Login for email: {}", email);

        return processSsoLogin(
                username,
                email,
                firstName,
                lastName,
                samlUser.getName(),
                User.AuthProvider.SAML,
                registrationId
        );
    }

    // Helper to find the first matching OIDC claim
    private String findOidcAttribute(Map<String, Object> claims, String... keys) {
        for (String key : keys) {
            if (claims.containsKey(key) && claims.get(key) != null) {
                return claims.get(key).toString();
            }
        }
        return null;
    }

    // Helper to find the first matching SAML attribute
    private String findSamlAttribute(Map<String, List<Object>> attributes, String... keys) {
        for (String key : keys) {
            if (attributes.containsKey(key) && attributes.get(key) != null && !attributes.get(key).isEmpty()) {
                Object value = attributes.get(key).get(0);
                if (value != null) {
                    return value.toString();
                }
            }
        }
        return null;
    }


    /**
     * UPDATED: Generic method to find or create an SSO user
     */
    @Transactional
    public User processSsoLogin(String username, String email, String firstName, String lastName, String providerId, User.AuthProvider provider, String registrationId) {
        if (email == null || email.isEmpty()) {
            log.error("Email from SSO provider ({}) is null or empty. Cannot process login.", provider);
            throw new IllegalArgumentException("Email from SSO provider cannot be null");
        }
        log.info("Processing SSO login for email: {}, provider: {}, providerId: {}", email, provider, providerId);

        User user = userRepository.findByProviderId(providerId)
                .or(() -> {
                    log.warn("User not found by providerId {}. Attempting lookup by email: {}", providerId, email);
                    return userRepository.findByEmail(email);
                })
                .map(existingUser -> {
                    log.info("Found existing user by email or providerId: {}. Updating details.", email);
                    existingUser.setAuthProvider(provider);
                    existingUser.setProviderId(providerId);
                    existingUser.setLastLogin(LocalDateTime.now());
                    if (!StringUtils.hasText(existingUser.getFirstName()) && StringUtils.hasText(firstName)) {
                        existingUser.setFirstName(firstName);
                    }
                    if (!StringUtils.hasText(existingUser.getLastName()) && StringUtils.hasText(lastName)) {
                        existingUser.setLastName(lastName);
                    }
                    return userRepository.save(existingUser);
                })
                .orElseGet(() -> {
                    log.info("Creating new SSO user via {} for email: {}", provider, email);

                    // --- "TRY/FALLBACK" USERNAME LOGIC ---
                    String finalUsername;
                    if (StringUtils.hasText(username) && !userRepository.existsByUsername(username)) {
                        // Use the username from IdP if it's provided and available
                        finalUsername = username;
                        log.info("Using provided username from IdP: {}", finalUsername);
                    } else {
                        // Fallback to generating a unique username
                        if (StringUtils.hasText(username)) {
                            log.warn("Username '{}' from IdP already exists. Generating a unique username.", username);
                        }
                        finalUsername = generateUniqueUsername(email, registrationId);
                        log.info("Generated unique username: {}", finalUsername);
                    }
                    // --- END LOGIC ---

                    User newUser = User.builder()
                            .username(finalUsername)
                            .email(email)
                            .password(passwordEncoder.encode(generateRandomPassword()))
                            .firstName(firstName)
                            .lastName(lastName)
                            .authProvider(provider)
                            .providerId(providerId)
                            .roles("ROLE_USER")
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

    private String generateUniqueUsername(String email, String registrationId) {
        String cleanRegId = registrationId.replaceAll("[^a-zA-Z0-9_]", "_");

        String baseUsername = email.split("@")[0].replaceAll("[^a-zA-Z0-9]", "_") + "_" + cleanRegId;

        if (baseUsername.length() > 40) {
            baseUsername = baseUsername.substring(0, 40);
        }

        if (!userRepository.existsByUsername(baseUsername)) {
            return baseUsername;
        }

        String finalUsername = baseUsername;
        int counter = 1;
        while (userRepository.existsByUsername(finalUsername)) {
            finalUsername = baseUsername + "_" + counter++;
            if (finalUsername.length() > 50) {
                finalUsername = baseUsername.substring(0, 40) + "_" + counter++;
            }
        }
        return finalUsername;
    }
}