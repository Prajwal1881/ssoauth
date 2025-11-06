package com.example.ssoauth.service;

import com.example.ssoauth.config.TenantContext;
import com.example.ssoauth.dto.*;
import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.entity.SsoProviderType;
import com.example.ssoauth.entity.Tenant;
import com.example.ssoauth.entity.User;
import com.example.ssoauth.exception.ResourceAlreadyExistsException;
import com.example.ssoauth.exception.SSOAuthenticationException;
import com.example.ssoauth.repository.TenantRepository;
import com.example.ssoauth.repository.UserRepository;
import com.example.ssoauth.security.JwtTokenProvider;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;


@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final SsoConfigService ssoConfigService;
    private final TenantRepository tenantRepository;

    @Transactional
    public JwtAuthResponse signIn(SignInRequest signInRequest) {

        // --- FIX: Read Long ID from context ---
        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) {
            // Main domain login.
            Optional<User> userOpt = userRepository.findByUsernameOrEmailAndTenantIsNull(
                    signInRequest.getUsernameOrEmail(), signInRequest.getUsernameOrEmail());

            if (userOpt.isPresent() && !userOpt.get().hasRole("ROLE_SUPER_ADMIN")) {
                log.warn("Tenant user {} attempted login from main domain. Denied.", signInRequest.getUsernameOrEmail());
                throw new BadCredentialsException("Please use your organization's login URL.");
            }
        }
        // --- End Fix ---

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        signInRequest.getUsernameOrEmail(),
                        signInRequest.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String username = authentication.getName();

        // --- FIX: Re-fetch user based on new context ---
        Optional<User> userOpt;
        // Read tenantId *again* as it's set by CustomUserDetailsService during authenticate()
        Long authTenantId = TenantContext.getCurrentTenant();

        if (authTenantId != null) {
            userOpt = userRepository.findByTenantIdAndUsernameOrTenantIdAndEmail(authTenantId, username, authTenantId, username);
        } else {
            userOpt = userRepository.findByUsernameOrEmailAndTenantIsNull(username, username);
        }

        User user = userOpt.orElseThrow(() -> new RuntimeException("User not found after authentication: " + username));
        // --- End Fix ---

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
        // --- FIX: Resolve tenant from Long ID ---
        Long tenantId = TenantContext.getCurrentTenant();
        Tenant tenant = null;

        if (tenantId != null) {
            tenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> new EntityNotFoundException("Invalid tenant: " + tenantId));

            if (userRepository.existsByUsernameAndTenantId(signUpRequest.getUsername(), tenantId)) {
                throw new ResourceAlreadyExistsException("Username is already taken for this tenant!");
            }
            if (userRepository.existsByEmailAndTenantId(signUpRequest.getEmail(), tenantId)) {
                throw new ResourceAlreadyExistsException("Email is already in use for this tenant!");
            }
        } else {
            // Super-admin signup (or main domain)
            if (userRepository.existsByUsernameAndTenantIdIsNull(signUpRequest.getUsername())) {
                throw new ResourceAlreadyExistsException("Username is already taken!");
            }
            if (userRepository.existsByEmailAndTenantIdIsNull(signUpRequest.getEmail())) {
                throw new ResourceAlreadyExistsException("Email is already in use!");
            }
        }
        // --- End Fix ---

        User user = User.builder()
                .username(signUpRequest.getUsername())
                .email(signUpRequest.getEmail())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .firstName(signUpRequest.getFirstName())
                .lastName(signUpRequest.getLastName())
                .authProvider(User.AuthProvider.LOCAL)
                .roles(StringUtils.hasText(signUpRequest.getRoles()) ? signUpRequest.getRoles() : "ROLE_USER")
                .tenant(tenant)
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


    @Transactional
    public User processOidcLogin(OidcUser oidcUser) {
        // --- FIX: Resolve tenantId from context ---
        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) {
            throw new SSOAuthenticationException("OIDC login failed: No tenant context found.");
        }
        // --- End Fix ---

        String registrationId = (String) oidcUser.getAttributes().get("registrationId");
        if (registrationId == null) {
            // SsoConfigService.getAllConfigEntities() will be filtered by the Aspect
            registrationId = ssoConfigService.getAllConfigEntities().stream()
                    .filter(c -> c.getProviderType() == SsoProviderType.OIDC && c.isEnabled())
                    .findFirst()
                    .map(SsoProviderConfig::getProviderId)
                    .orElseThrow(() -> new SSOAuthenticationException("Could not determine OIDC registrationId or no OIDC provider enabled"));
        }

        final String finalRegistrationId = registrationId;

        // SsoConfigService.getConfigByProviderId() is already tenant-aware
        SsoProviderConfig config = ssoConfigService.getConfigByProviderId(registrationId)
                .orElseThrow(() -> new SSOAuthenticationException("No OIDC config found for: " + finalRegistrationId));

        // This check is good redundancy
        if (!config.getTenant().getId().equals(tenantId)) {
            throw new SSOAuthenticationException("OIDC config mismatch: Provider does not belong to current tenant.");
        }

        Map<String, Object> claims = oidcUser.getClaims();

        log.info("--- OIDC ATTRIBUTE DUMP (START) ---");
        log.info("Provider: {}, Tenant: {}", config.getProviderId(), tenantId);
        claims.forEach((key, value) -> log.info("  Claim: '{}', Value: '{}'", key, value != null ? value.toString() : "null"));
        log.info("--- OIDC ATTRIBUTE DUMP (END) ---");

        String username = findOidcAttribute(claims, config.getUserNameAttribute(), "preferred_username", "username", "uid", "sub");
        String email = findOidcAttribute(claims, "email", "mail", "userPrincipalName");
        String firstName = findOidcAttribute(claims, "given_name", "firstName", "fn");
        String lastName = findOidcAttribute(claims, "family_name", "lastName", "sn");

        if (email == null) email = oidcUser.getEmail(); // Fallback
        if (username == null) username = email; // Fallback to email if username attribute is not found

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

    @Transactional
    public User processSamlLogin(Saml2AuthenticatedPrincipal samlUser) {
        // --- FIX: Resolve tenantId from context ---
        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) {
            throw new SSOAuthenticationException("SAML login failed: No tenant context found.");
        }
        // --- End Fix ---

        String registrationId = samlUser.getRelyingPartyRegistrationId();

        // SsoConfigService.getConfigByProviderId() is already tenant-aware
        SsoProviderConfig config = ssoConfigService.getConfigByProviderId(registrationId)
                .orElseThrow(() -> new SSOAuthenticationException("No SAML config found for: " + registrationId));

        if (!config.getTenant().getId().equals(tenantId)) {
            throw new SSOAuthenticationException("SAML config mismatch: Provider does not belong to current tenant.");
        }

        Map<String, List<Object>> attributes = samlUser.getAttributes();

        log.info("--- SAML ATTRIBUTE DUMP (START) ---");
        log.info("Provider: {}, Tenant: {}", config.getProviderId(), tenantId);
        attributes.forEach((key, value) -> log.info("  Attribute: '{}', Value: '{}'", key,
                value != null ? value.stream().map(Object::toString).collect(Collectors.joining(",")) : "null"
        ));
        log.info("--- SAML ATTRIBUTE DUMP (END) ---");

        String username = findSamlAttribute(attributes, config.getUserNameAttribute(), "username", "uid", "preferred_username");
        String email = findSamlAttribute(attributes, "email", "mail", "userPrincipalName", "NameID");
        String firstName = findSamlAttribute(attributes, "firstName", "givenName", "fn");
        String lastName = findSamlAttribute(attributes, "lastName", "sn");

        if (email == null) email = samlUser.getName(); // Fallback to NameID
        if (username == null) username = email; // Fallback to email

        log.info("Processing SAML Login for email: {}", email);

        return processSsoLogin(
                username,
                email,
                firstName,
                lastName,
                samlUser.getName(), // Use NameID as the provider-specific ID
                User.AuthProvider.SAML,
                registrationId
        );
    }

    private String findOidcAttribute(Map<String, Object> claims, String... keys) {
        for (String key : keys) {
            if (key != null && claims.containsKey(key) && claims.get(key) != null) {
                return claims.get(key).toString();
            }
        }
        return null;
    }

    private String findSamlAttribute(Map<String, List<Object>> attributes, String... keys) {
        for (String key : keys) {
            if (key != null && attributes.containsKey(key) && attributes.get(key) != null && !attributes.get(key).isEmpty()) {
                Object value = attributes.get(key).get(0);
                if (value != null) {
                    return value.toString();
                }
            }
        }
        return null;
    }

    @Transactional
    public User processSsoLogin(String username, String email, String firstName, String lastName, String providerId, User.AuthProvider provider, String registrationId) {
        // --- FIX: Resolve tenantId from context ---
        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) {
            throw new SSOAuthenticationException("Cannot process SSO login without a tenant context.");
        }
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new SSOAuthenticationException("Invalid tenant: " + tenantId));
        // --- End Fix ---

        if (email == null || email.isEmpty()) {
            log.error("Email from SSO provider ({}) is null or empty. Cannot process login.", provider);
            throw new IllegalArgumentException("Email from SSO provider cannot be null");
        }
        log.info("Processing SSO login for email: {}, provider: {}, providerId: {}, tenant: {}", email, provider, providerId, tenantId);

        // The AspectJ filter will scope findByProviderId and findByEmailAndTenantId
        User user = userRepository.findByProviderId(providerId)
                .or(() -> {
                    log.warn("User not found by providerId {}. Attempting lookup by email: {} in tenant: {}", providerId, email, tenantId);
                    return userRepository.findByEmailAndTenantId(email, tenantId);
                })
                .map(existingUser -> {
                    log.info("Found existing user by email or providerId: {}. Updating details.", email);
                    existingUser.setAuthProvider(provider);
                    // Only update providerId if it's not already set, or if it matches
                    if (!StringUtils.hasText(existingUser.getProviderId())) {
                        existingUser.setProviderId(providerId);
                    }
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
                    log.info("Creating new SSO user via {} for email: {} in tenant: {}", provider, email, tenantId);

                    String finalUsername;
                    if (StringUtils.hasText(username) && !userRepository.existsByUsernameAndTenantId(username, tenantId)) {
                        finalUsername = username;
                        log.info("Using provided username from IdP: {}", finalUsername);
                    } else {
                        if (StringUtils.hasText(username)) {
                            log.warn("Username '{}' from IdP already exists in tenant {}. Generating a unique username.", username, tenantId);
                        }
                        finalUsername = generateUniqueUsername(email, tenantId);
                        log.info("Generated unique username: {}", finalUsername);
                    }

                    User newUser = User.builder()
                            .username(finalUsername)
                            .email(email)
                            .password(passwordEncoder.encode(generateRandomPassword()))
                            .firstName(firstName)
                            .lastName(lastName)
                            .authProvider(provider)
                            .providerId(providerId)
                            .tenant(tenant)
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

    private String generateUniqueUsername(String email, Long tenantId) {
        String baseUsername = email.split("@")[0].replaceAll("[^a-zA-Z0-9]", "_");

        if (baseUsername.length() > 40) {
            baseUsername = baseUsername.substring(0, 40);
        }

        if (!userRepository.existsByUsernameAndTenantId(baseUsername, tenantId)) {
            return baseUsername;
        }

        String finalUsername = baseUsername;
        int counter = 1;
        while (userRepository.existsByUsernameAndTenantId(finalUsername, tenantId)) {
            finalUsername = baseUsername + "_" + counter++;
            if (finalUsername.length() > 50) {
                // Handle very long base usernames + counter
                finalUsername = baseUsername.substring(0, Math.min(baseUsername.length(), 40)) + "_" + counter;
            }
        }
        return finalUsername;
    }
}