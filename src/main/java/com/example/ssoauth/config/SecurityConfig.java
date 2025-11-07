package com.example.ssoauth.config;

import com.example.ssoauth.security.JwtAuthenticationFilter;
import com.example.ssoauth.security.JwtAuthenticationEntryPoint;
import com.example.ssoauth.security.JwtTokenProvider;
import com.example.ssoauth.service.AuthService;
import com.example.ssoauth.entity.User;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
// NEW IMPORTS
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
// END NEW IMPORTS
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserDetailsService userDetailsService;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final DynamicClientRegistrationRepository dynamicOidcRepository;
    private final DynamicRelyingPartyRegistrationRepository dynamicSamlRepository;
    private final TenantIdentificationFilter tenantIdentificationFilter;
    private final DynamicKerberosConfig dynamicKerberosConfig;

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                          AuthenticationSuccessHandler oidcLoginSuccessHandler,
                                                          AuthenticationSuccessHandler samlLoginSuccessHandler,
                                                          AuthenticationSuccessHandler kerberosSuccessHandler
    ) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // ========================================
                // MODIFIED: KERBEROS/SPNEGO CONFIGURATION
                // ========================================
                .exceptionHandling(exception -> exception
                        // Add SpnegoEntryPoint to challenge the browser for a ticket
                        // It will fall back to JwtAuthenticationEntryPoint for /api/** requests
                        .authenticationEntryPoint(dynamicKerberosConfig.createSpnegoEntryPoint())
                )
                // --- END MODIFICATION ---

                .authorizeHttpRequests(auth -> auth
                        // ... (all your existing .requestMatchers)
                        .requestMatchers(
                                "/", "/login", "/signup", "/error",
                                "/css/**", "/js/**", "/images/**",
                                "/api/auth/**",
                                "/api/sso/enabled-providers",
                                "/api/public/branding",
                                "/api/sso/test-attributes/**",
                                "/oauth2/**",
                                "/login/oauth2/**",
                                "/login/jwt/callback",
                                "/saml2/**",
                                "/login/saml2/**",
                                "/dashboard",
                                "/admin/dashboard",
                                "/admin/sso-test-result",
                                "/super-admin/dashboard"
                        ).permitAll()
                        .requestMatchers(
                                "/api/admin/**"
                        ).hasRole("ADMIN")
                        .requestMatchers(
                                "/api/super-admin/**"
                        ).hasRole("SUPER_ADMIN")
                        .requestMatchers(
                                "/api/user/**"
                        ).hasAnyRole("USER", "ADMIN", "SUPER_ADMIN")
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .clientRegistrationRepository(dynamicOidcRepository)
                        .successHandler(oidcLoginSuccessHandler)
                )
                .saml2Login(saml2 -> saml2
                        .loginPage("/login")
                        .relyingPartyRegistrationRepository(dynamicSamlRepository)
                        .successHandler(samlLoginSuccessHandler)
                )

                // ========================================
                // MODIFIED: KERBEROS/SPNEGO CONFIGURATION
                // ========================================
                .addFilterBefore(
                        // This filter is now added UNCONDITIONALLY
                        dynamicKerberosConfig.createSpnegoFilter(
                                tenantAwareAuthenticationManager(), // Use the new tenant-aware manager
                                kerberosSuccessHandler
                        ),
                        UsernamePasswordAuthenticationFilter.class
                )
                // --- END MODIFICATION ---

                .authenticationProvider(authenticationProvider()) // Your local password provider
                .addFilterBefore(tenantIdentificationFilter, SecurityContextHolderFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * NEW: Creates a tenant-aware AuthenticationManager.
     * This manager will first try Kerberos (if enabled for the tenant)
     * and then fall back to local passwords (DaoAuthenticationProvider).
     */
    @Bean
    public AuthenticationManager tenantAwareAuthenticationManager() {
        // This is a lambda implementation of the AuthenticationManager interface
        return authentication -> {
            // 1. Check for tenant-specific Kerberos provider (per-request)
            // This is safe because TenantContext is set by TenantIdentificationFilter
            KerberosServiceAuthenticationProvider kerberosProvider =
                    dynamicKerberosConfig.createKerberosProvider();

            if (kerberosProvider != null) {
                try {
                    // Try to authenticate with Kerberos
                    log.debug("Attempting authentication with tenant-specific Kerberos provider...");
                    return kerberosProvider.authenticate(authentication);
                } catch (Exception e) {
                    // This is expected if the token is not a Kerberos token (e.g., it's a password login)
                    log.debug("Kerberos provider failed (likely not a Kerberos token), falling back to DAO: {}", e.getMessage());
                }
            }

            // 2. Fallback to local password (DAO) authentication
            log.debug("No Kerberos provider found or Kerberos failed, attempting with DAO provider.");
            return authenticationProvider().authenticate(authentication);
        };
    }

    /**
     * MODIFIED: This bean is now used as the fallback provider
     * for local username/password authentication.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    /**
     * MODIFIED: This bean now exposes the new tenant-aware manager
     * to the Spring context for use in your /api/auth/signin endpoint.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        // Return the composite, tenant-aware manager
        return tenantAwareAuthenticationManager();
    }

    // --- REMOVED ---
    // The old createKerberosFilterIfEnabled and kerberosAuthenticationManager beans
    // are no longer needed as they are replaced by the logic above.

    // ========================================
    // SUCCESS HANDLERS & OTHER BEANS
    // (No changes below this line)
    // ========================================

    @Bean
    public AuthenticationSuccessHandler kerberosSuccessHandler(
            AuthService authService,
            JwtTokenProvider jwtTokenProvider
    ) {
        return (request, response, authentication) -> {
            HttpSession session = request.getSession();
            String testProviderId = (String) session.getAttribute("sso_test_provider_id");

            // Extract Kerberos principal (format: user@REALM)
            String kerberosPrincipal = authentication.getName();
            log.info("Kerberos authentication successful for: {}", kerberosPrincipal);

            // Check if this is an attribute test
            if (testProviderId != null) {
                log.info("Kerberos login is an attribute test for: {}", testProviderId);
                Map<String, String> attributes = new HashMap<>();
                attributes.put("principal", kerberosPrincipal);

                if (kerberosPrincipal.contains("@")) {
                    attributes.put("realm", kerberosPrincipal.split("@")[1]);
                    attributes.put("username", kerberosPrincipal.split("@")[0]);
                } else {
                    attributes.put("username", kerberosPrincipal);
                }

                session.setAttribute("sso_test_attributes", attributes);
                response.sendRedirect("/admin/sso-test-result");
                return;
            }

            // --- Normal Login Flow ---
            User appUser = authService.processKerberosLogin(kerberosPrincipal);
            String accessToken = jwtTokenProvider.generateTokenFromUsername(appUser.getUsername());

            // Redirect based on role
            String targetUrl = "/dashboard";
            if (appUser.hasRole("ROLE_SUPER_ADMIN")) {
                targetUrl = "/super-admin/dashboard";
            } else if (appUser.hasRole("ROLE_ADMIN")) {
                targetUrl = "/admin/dashboard";
            }

            String redirectUrl = targetUrl + "?token=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
            response.sendRedirect(redirectUrl);
        };
    }

    @Bean
    public AuthenticationSuccessHandler oidcLoginSuccessHandler(
            AuthService authService,
            JwtTokenProvider jwtTokenProvider
    ) {
        return (request, response, authentication) -> {
            HttpSession session = request.getSession();
            String testProviderId = (String) session.getAttribute("sso_test_provider_id");
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();

            if (testProviderId != null) {
                log.info("OIDC login is an attribute test for: {}", testProviderId);
                Map<String, String> attributes = new HashMap<>();
                oidcUser.getClaims().forEach((key, value) -> {
                    attributes.put(key, value.toString());
                });

                session.setAttribute("sso_test_attributes", attributes);
                response.sendRedirect("/admin/sso-test-result");
                return;
            }

            User appUser = authService.processOidcLogin(oidcUser);
            String accessToken = jwtTokenProvider.generateTokenFromUsername(appUser.getUsername());

            String targetUrl = "/dashboard";
            if (appUser.hasRole("ROLE_SUPER_ADMIN")) {
                targetUrl = "/super-admin/dashboard";
            } else if (appUser.hasRole("ROLE_ADMIN")) {
                targetUrl = "/admin/dashboard";
            }

            String redirectUrl = targetUrl + "?token=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
            response.sendRedirect(redirectUrl);
        };
    }

    @Bean
    public AuthenticationSuccessHandler samlLoginSuccessHandler(
            AuthService authService,
            JwtTokenProvider jwtTokenProvider
    ) {
        return (request, response, authentication) -> {
            HttpSession session = request.getSession();
            String testProviderId = (String) session.getAttribute("sso_test_provider_id");
            Saml2AuthenticatedPrincipal samlUser = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();

            if (testProviderId != null && testProviderId.equals(samlUser.getRelyingPartyRegistrationId())) {
                log.info("SAML login is an attribute test for: {}", testProviderId);
                Map<String, String> attributes = new HashMap<>();
                attributes.put("NameID", samlUser.getName());
                samlUser.getAttributes().forEach((key, value) -> {
                    String aValue = value.stream()
                            .map(Object::toString)
                            .collect(Collectors.joining(", "));
                    attributes.put(key, aValue);
                });

                session.setAttribute("sso_test_attributes", attributes);
                response.sendRedirect("/admin/sso-test-result");
                return;
            }

            User appUser = authService.processSamlLogin(samlUser);
            String accessToken = jwtTokenProvider.generateTokenFromUsername(appUser.getUsername());

            String targetUrl = "/dashboard";
            if (appUser.hasRole("ROLE_SUPER_ADMIN")) {
                targetUrl = "/super-admin/dashboard";
            } else if (appUser.hasRole("ROLE_ADMIN")) {
                targetUrl = "/admin/dashboard";
            }

            String redirectUrl = targetUrl + "?token=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
            response.sendRedirect(redirectUrl);
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOriginPattern("*");
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}