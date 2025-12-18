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
        log.debug("SignIn attempt started for user: {}", signInRequest.getUsernameOrEmail());

        Long tenantId = TenantContext.getCurrentTenant();
        log.debug("Current tenant context: {}", tenantId);

        try {
            if (tenantId == null) {
                log.debug("Root domain login attempt for user: {}", signInRequest.getUsernameOrEmail());
                Optional<User> userOpt = userRepository.findByUsernameOrEmailAndTenantIsNull(
                        signInRequest.getUsernameOrEmail(), signInRequest.getUsernameOrEmail());

                if (userOpt.isPresent() && !userOpt.get().hasRole("ROLE_SUPER_ADMIN")) {
                    log.warn("Tenant user {} attempted login from main domain - Access denied", signInRequest.getUsernameOrEmail());
                    throw new BadCredentialsException("Please use your organization's login URL.");
                }
            }

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            signInRequest.getUsernameOrEmail(),
                            signInRequest.getPassword()
                    )
            );

            log.debug("Authentication successful for user: {}", signInRequest.getUsernameOrEmail());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String username = authentication.getName();

            Optional<User> userOpt;
            Long authTenantId = TenantContext.getCurrentTenant();

            if (authTenantId != null) {
                log.debug("Fetching tenant user for tenantId: {}", authTenantId);
                userOpt = userRepository.findByTenantIdAndUsernameOrTenantIdAndEmail(authTenantId, username, authTenantId, username);
            } else {
                log.debug("Fetching super admin user");
                userOpt = userRepository.findByUsernameOrEmailAndTenantIsNull(username, username);
            }

            User user = userOpt.orElseThrow(() -> {
                log.error("User not found after successful authentication: {}", username);
                return new RuntimeException("User not found after authentication: " + username);
            });

            userRepository.updateLastLogin(user.getId(), LocalDateTime.now());
            log.debug("Updated last login timestamp for user ID: {}", user.getId());

            String accessToken = jwtTokenProvider.generateToken(authentication);
            String refreshToken = jwtTokenProvider.generateRefreshToken(username);

            log.info("SignIn successful for user: {} (ID: {}), roles: {}", username, user.getId(), user.getRoles());

            return JwtAuthResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(jwtTokenProvider.getJwtExpirationMs())
                    .userInfo(mapToUserInfo(user))
                    .build();

        } catch (BadCredentialsException e) {
            log.warn("SignIn failed - Invalid credentials for user: {}", signInRequest.getUsernameOrEmail());
            throw e;
        } catch (Exception e) {
            log.error("SignIn failed with unexpected error for user: {}", signInRequest.getUsernameOrEmail(), e);
            throw e;
        }
    }

    @Transactional
    public JwtAuthResponse signUp(SignUpRequest signUpRequest) {
        log.debug("SignUp attempt started for username: {}, email: {}", signUpRequest.getUsername(), signUpRequest.getEmail());

        Long tenantId = TenantContext.getCurrentTenant();
        log.debug("Signup tenant context: {}", tenantId);

        Tenant tenant = null;

        try {
            if (tenantId != null) {
                log.debug("Fetching tenant for ID: {}", tenantId);
                tenant = tenantRepository.findById(tenantId)
                        .orElseThrow(() -> {
                            log.error("Tenant not found for ID: {}", tenantId);
                            return new EntityNotFoundException("Invalid tenant: " + tenantId);
                        });

                if (userRepository.existsByUsernameAndTenantId(signUpRequest.getUsername(), tenantId)) {
                    log.warn("SignUp failed - Username already exists: {} for tenant: {}", signUpRequest.getUsername(), tenantId);
                    throw new ResourceAlreadyExistsException("Username is already taken for this tenant!");
                }
                if (userRepository.existsByEmailAndTenantId(signUpRequest.getEmail(), tenantId)) {
                    log.warn("SignUp failed - Email already exists: {} for tenant: {}", signUpRequest.getEmail(), tenantId);
                    throw new ResourceAlreadyExistsException("Email is already in use for this tenant!");
                }
            } else {
                if (userRepository.existsByUsernameAndTenantIdIsNull(signUpRequest.getUsername())) {
                    log.warn("SignUp failed - Username already exists: {} (root domain)", signUpRequest.getUsername());
                    throw new ResourceAlreadyExistsException("Username is already taken!");
                }
                if (userRepository.existsByEmailAndTenantIdIsNull(signUpRequest.getEmail())) {
                    log.warn("SignUp failed - Email already exists: {} (root domain)", signUpRequest.getEmail());
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
            log.info("User created successfully: {} (ID: {}), tenant: {}", savedUser.getUsername(), savedUser.getId(), tenantId);

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            signUpRequest.getUsername(),
                            signUpRequest.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String accessToken = jwtTokenProvider.generateToken(authentication);
            String refreshToken = jwtTokenProvider.generateRefreshToken(savedUser.getUsername());

            log.debug("Generated tokens for new user: {}", savedUser.getUsername());

            return JwtAuthResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(jwtTokenProvider.getJwtExpirationMs())
                    .userInfo(mapToUserInfo(savedUser))
                    .build();

        } catch (ResourceAlreadyExistsException e) {
            log.warn("SignUp validation failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("SignUp failed with unexpected error for username: {}", signUpRequest.getUsername(), e);
            throw e;
        }
    }

    @Transactional
    public User processOidcLogin(OidcUser oidcUser, String registrationId) {
        log.debug("Processing OIDC login - registrationId: {}", registrationId);

        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) {
            log.error("OIDC login failed - No tenant context found");
            throw new SSOAuthenticationException("OIDC login failed: No tenant context found.");
        }

        log.debug("OIDC login for tenant: {}", tenantId);

        String suffix = "-" + tenantId;
        final String dbProviderId = registrationId.endsWith(suffix)
                ? registrationId.substring(0, registrationId.length() - suffix.length())
                : registrationId;

        if (registrationId.endsWith(suffix)) {
            log.debug("Parsed internal OIDC ID '{}' to DB Provider ID '{}'", registrationId, dbProviderId);
        }

        try {
            SsoProviderConfig config = ssoConfigService.getConfigByProviderId(dbProviderId)
                    .orElseThrow(() -> {
                        log.error("No OIDC config found for: {}", dbProviderId);
                        return new SSOAuthenticationException("No OIDC config found for: " + dbProviderId);
                    });

            if (!config.getTenant().getId().equals(tenantId)) {
                log.error("Security violation - OIDC config '{}' belongs to tenant {}, but current tenant is {}",
                        dbProviderId, config.getTenant().getId(), tenantId);
                throw new SSOAuthenticationException("OIDC config mismatch: Provider does not belong to current tenant.");
            }

            if (config.getProviderType() != SsoProviderType.OIDC) {
                log.error("Provider {} is not an OIDC provider, type: {}", dbProviderId, config.getProviderType());
                throw new SSOAuthenticationException("Provider " + dbProviderId + " is not an OIDC provider");
            }

            Map<String, Object> claims = oidcUser.getClaims();
            log.debug("Processing OIDC Login for tenant {}. Attributes count: {}", tenantId, claims.size());

            String username = findOidcAttribute(claims,
                    config.getUserNameAttribute(), "preferred_username", "username", "uid", "sub");
            String email = findOidcAttribute(claims, "email", "mail", "userPrincipalName");
            String firstName = findOidcAttribute(claims, "given_name", "firstName", "fn");
            String lastName = findOidcAttribute(claims, "family_name", "lastName", "sn");

            if (email == null) email = oidcUser.getEmail();
            if (username == null) username = email;

            log.info("OIDC user authenticated: username={}, email={}, provider={}", username, email, dbProviderId);

            return processSsoLogin(
                    username,
                    email,
                    firstName,
                    lastName,
                    oidcUser.getSubject(),
                    User.AuthProvider.OIDC,
                    config.getProviderId()
            );

        } catch (SSOAuthenticationException e) {
            log.warn("OIDC login failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during OIDC login processing", e);
            throw new SSOAuthenticationException("OIDC login failed: " + e.getMessage(), e);
        }
    }

    @Transactional
    public User processSamlLogin(Saml2AuthenticatedPrincipal samlUser) {
        log.debug("Processing SAML login");

        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) {
            log.error("SAML login failed - No tenant context found");
            throw new SSOAuthenticationException("SAML login failed: No tenant context found.");
        }

        String registrationId = samlUser.getRelyingPartyRegistrationId();
        log.debug("SAML login for tenant: {}, registrationId: {}", tenantId, registrationId);

        try {
            SsoProviderConfig config = ssoConfigService.getConfigByProviderId(registrationId)
                    .orElseThrow(() -> {
                        log.error("No SAML config found for: {}", registrationId);
                        return new SSOAuthenticationException("No SAML config found for: " + registrationId);
                    });

            if (!config.getTenant().getId().equals(tenantId)) {
                log.error("Security violation - SAML config mismatch for registrationId: {}", registrationId);
                throw new SSOAuthenticationException("SAML config mismatch: Provider does not belong to current tenant.");
            }

            Map<String, List<Object>> attributes = samlUser.getAttributes();
            log.debug("Processing SAML Login for tenant {}. Attributes count: {}", tenantId, attributes.size());

            String username = findSamlAttribute(attributes, config.getUserNameAttribute(), "username", "uid", "preferred_username");
            String email = findSamlAttribute(attributes, "email", "mail", "userPrincipalName", "NameID");
            String firstName = findSamlAttribute(attributes, "firstName", "givenName", "fn");
            String lastName = findSamlAttribute(attributes, "lastName", "sn");

            if (email == null) email = samlUser.getName();
            if (username == null) username = email;

            log.info("SAML user authenticated: username={}, email={}, registrationId={}", username, email, registrationId);

            return processSsoLogin(
                    username,
                    email,
                    firstName,
                    lastName,
                    samlUser.getName(),
                    User.AuthProvider.SAML,
                    registrationId
            );

        } catch (SSOAuthenticationException e) {
            log.warn("SAML login failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during SAML login processing", e);
            throw new SSOAuthenticationException("SAML login failed: " + e.getMessage(), e);
        }
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
    public User processSsoLogin(String username, String email, String firstName, String lastName,
                                String providerId, User.AuthProvider provider, String registrationId) {
        log.debug("Processing SSO login - email: {}, providerId: {}, provider: {}", email, providerId, provider);

        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) {
            log.error("Cannot process SSO login without tenant context");
            throw new SSOAuthenticationException("Cannot process SSO login without a tenant context.");
        }

        try {
            Tenant tenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> {
                        log.error("Invalid tenant ID: {}", tenantId);
                        return new SSOAuthenticationException("Invalid tenant: " + tenantId);
                    });

            if (email == null || email.isEmpty()) {
                log.error("Email from SSO provider ({}) is null or empty for providerId: {}", provider, providerId);
                throw new IllegalArgumentException("Email from SSO provider cannot be null");
            }

            log.debug("Looking up user by providerId: {} in tenant: {}", providerId, tenantId);

            User user = userRepository.findByProviderIdAndTenantId(providerId, tenantId)
                    .or(() -> {
                        log.debug("User not found by providerId, attempting lookup by email: {}", email);
                        return userRepository.findByEmailAndTenantId(email, tenantId);
                    })
                    .map(existingUser -> {
                        log.info("Found existing user (ID: {}) for email/providerId in tenant {}, updating details",
                                existingUser.getId(), tenantId);
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

                        User updated = userRepository.save(existingUser);
                        log.debug("Updated existing user successfully");
                        return updated;
                    })
                    .orElseGet(() -> {
                        log.info("Creating new SSO user in Tenant {} via {}", tenantId, provider);

                        String finalUsername;
                        if (StringUtils.hasText(username) && !userRepository.existsByUsernameAndTenantId(username, tenantId)) {
                            finalUsername = username;
                        } else {
                            if (StringUtils.hasText(username)) {
                                log.warn("Username '{}' already exists in tenant {}, generating unique username", username, tenantId);
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
                        User saved = userRepository.save(newUser);
                        log.info("Created new SSO user successfully: {} (ID: {})", saved.getUsername(), saved.getId());
                        return saved;
                    });

            return user;

        } catch (IllegalArgumentException | SSOAuthenticationException e) {
            log.warn("SSO login processing failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during SSO login processing for email: {}", email, e);
            throw new SSOAuthenticationException("SSO login processing failed: " + e.getMessage(), e);
        }
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
        log.debug("Generating unique username for email: {}", email);

        String baseUsername = email.split("@")[0].replaceAll("[^a-zA-Z0-9]", "_").toLowerCase();

        if (baseUsername.length() > 40) {
            baseUsername = baseUsername.substring(0, 40);
        }

        if (!userRepository.existsByUsernameAndTenantId(baseUsername, tenantId)) {
            log.debug("Generated username: {}", baseUsername);
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

        log.debug("Generated unique username with counter: {}", finalUsername);
        return finalUsername;
    }
}