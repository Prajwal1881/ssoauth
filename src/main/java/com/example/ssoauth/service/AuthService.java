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

    // ... (signIn and signUp methods remain unchanged) ...
    @Transactional
    public JwtAuthResponse signIn(SignInRequest signInRequest) {
        // ... existing implementation ...
        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) {
            Optional<User> userOpt = userRepository.findByUsernameOrEmailAndTenantIsNull(
                    signInRequest.getUsernameOrEmail(), signInRequest.getUsernameOrEmail());

            if (userOpt.isPresent() && !userOpt.get().hasRole("ROLE_SUPER_ADMIN")) {
                log.warn("Tenant user {} attempted login from main domain. Denied.", signInRequest.getUsernameOrEmail());
                throw new BadCredentialsException("Please use your organization's login URL.");
            }
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        signInRequest.getUsernameOrEmail(),
                        signInRequest.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String username = authentication.getName();

        Optional<User> userOpt;
        Long authTenantId = TenantContext.getCurrentTenant();

        if (authTenantId != null) {
            userOpt = userRepository.findByTenantIdAndUsernameOrTenantIdAndEmail(authTenantId, username, authTenantId, username);
        } else {
            userOpt = userRepository.findByUsernameOrEmailAndTenantIsNull(username, username);
        }

        User user = userOpt.orElseThrow(() -> new RuntimeException("User not found after authentication: " + username));

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
        // ... existing implementation ...
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
            if (userRepository.existsByUsernameAndTenantIdIsNull(signUpRequest.getUsername())) {
                throw new ResourceAlreadyExistsException("Username is already taken!");
            }
            if (userRepository.existsByEmailAndTenantIdIsNull(signUpRequest.getEmail())) {
                throw new ResourceAlreadyExistsException("Email is already in use!");
            }
        }

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

    /**
     * Process OIDC login with explicit registrationId
     */
    @Transactional
    public User processOidcLogin(OidcUser oidcUser, String registrationId) {
        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) {
            throw new SSOAuthenticationException("OIDC login failed: No tenant context found.");
        }

        // --- FIX: Handle unique internal ID format safely (Effectively Final) ---
        String suffix = "-" + tenantId;

        // Use a final variable for the DB lookup ID
        final String dbProviderId = registrationId.endsWith(suffix)
                ? registrationId.substring(0, registrationId.length() - suffix.length())
                : registrationId;

        if (registrationId.endsWith(suffix)) {
            log.debug("Parsed internal OIDC ID '{}' to DB Provider ID '{}'", registrationId, dbProviderId);
        }
        // --- END FIX ---

        log.debug("Processing OIDC login for registrationId: {} in tenant: {}", dbProviderId, tenantId);

        // Validate that the config exists and belongs to this tenant
        // Now 'dbProviderId' is effectively final and can be used in the lambda below
        SsoProviderConfig config = ssoConfigService.getConfigByProviderId(dbProviderId)
                .orElseThrow(() -> new SSOAuthenticationException(
                        "No OIDC config found for: " + dbProviderId));

        // Security check: Ensure the config belongs to the current tenant
        if (!config.getTenant().getId().equals(tenantId)) {
            log.error("Security violation: OIDC config '{}' belongs to tenant {}, but current tenant is {}",
                    dbProviderId, config.getTenant().getId(), tenantId);
            throw new SSOAuthenticationException(
                    "OIDC config mismatch: Provider does not belong to current tenant.");
        }

        if (config.getProviderType() != SsoProviderType.OIDC) {
            throw new SSOAuthenticationException(
                    "Provider " + dbProviderId + " is not an OIDC provider");
        }

        Map<String, Object> claims = oidcUser.getClaims();
        log.debug("Processing OIDC Login for tenant {}. Attributes: {}", tenantId, claims);

        // Extract user attributes with fallbacks
        String username = findOidcAttribute(claims,
                config.getUserNameAttribute(), "preferred_username", "username", "uid", "sub");
        String email = findOidcAttribute(claims, "email", "mail", "userPrincipalName");
        String firstName = findOidcAttribute(claims, "given_name", "firstName", "fn");
        String lastName = findOidcAttribute(claims, "family_name", "lastName", "sn");

        if (email == null) email = oidcUser.getEmail();
        if (username == null) username = email;

        log.info("OIDC user authenticated: username={}, email={}, provider={}",
                username, email, dbProviderId);

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

    // ... (rest of the class methods: processSamlLogin, processSsoLogin, etc. remain unchanged) ...
    @Transactional
    public User processSamlLogin(Saml2AuthenticatedPrincipal samlUser) {
        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) {
            throw new SSOAuthenticationException("SAML login failed: No tenant context found.");
        }

        String registrationId = samlUser.getRelyingPartyRegistrationId();

        SsoProviderConfig config = ssoConfigService.getConfigByProviderId(registrationId)
                .orElseThrow(() -> new SSOAuthenticationException("No SAML config found for: " + registrationId));

        if (!config.getTenant().getId().equals(tenantId)) {
            throw new SSOAuthenticationException("SAML config mismatch: Provider does not belong to current tenant.");
        }

        Map<String, List<Object>> attributes = samlUser.getAttributes();

        log.debug("Processing SAML Login for tenant {}. Attributes: {}", tenantId, attributes);

        String username = findSamlAttribute(attributes, config.getUserNameAttribute(), "username", "uid", "preferred_username");
        String email = findSamlAttribute(attributes, "email", "mail", "userPrincipalName", "NameID");
        String firstName = findSamlAttribute(attributes, "firstName", "givenName", "fn");
        String lastName = findSamlAttribute(attributes, "lastName", "sn");

        if (email == null) email = samlUser.getName();
        if (username == null) username = email;

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
        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) {
            throw new SSOAuthenticationException("Cannot process SSO login without a tenant context.");
        }
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new SSOAuthenticationException("Invalid tenant: " + tenantId));

        if (email == null || email.isEmpty()) {
            log.error("Email from SSO provider ({}) is null or empty. Cannot process login.", provider);
            throw new IllegalArgumentException("Email from SSO provider cannot be null");
        }
        log.info("Processing SSO login for email: {}, providerId: {}, tenant: {}", email, providerId, tenantId);

        User user = userRepository.findByProviderIdAndTenantId(providerId, tenantId)
                .or(() -> {
                    log.warn("User not found by providerId {} in tenant {}. Attempting lookup by email.", providerId, tenantId);
                    return userRepository.findByEmailAndTenantId(email, tenantId);
                })
                .map(existingUser -> {
                    log.info("Found existing user by email or providerId in CURRENT tenant. Updating details.");
                    existingUser.setAuthProvider(provider);

                    if (!StringUtils.hasText(existingUser.getProviderId()) || !existingUser.getProviderId().equals(providerId)) {
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
                    log.info("Creating new SSO user in Tenant {} via {}", tenantId, provider);

                    String finalUsername;
                    if (StringUtils.hasText(username) && !userRepository.existsByUsernameAndTenantId(username, tenantId)) {
                        finalUsername = username;
                    } else {
                        if (StringUtils.hasText(username)) {
                            log.warn("Username '{}' already exists in tenant {}. Generating unique username.", username, tenantId);
                        }
                        finalUsername = generateUniqueUsername(email, tenantId);
                    }

                    if (finalUsername != null) finalUsername = finalUsername.toLowerCase();

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
        String baseUsername = email.split("@")[0].replaceAll("[^a-zA-Z0-9]", "_").toLowerCase();

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
                finalUsername = baseUsername.substring(0, Math.min(baseUsername.length(), 40)) + "_" + counter;
            }
        }
        return finalUsername;
    }
}