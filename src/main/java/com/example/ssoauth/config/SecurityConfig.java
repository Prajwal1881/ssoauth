package com.example.ssoauth.config;

import com.example.ssoauth.security.JwtAuthenticationFilter;
import com.example.ssoauth.security.JwtAuthenticationEntryPoint;
import com.example.ssoauth.security.JwtTokenProvider;
import com.example.ssoauth.service.AuthService;
import com.example.ssoauth.entity.User;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpServletResponse;
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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.kerberos.authentication.KerberosServiceRequestToken;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
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
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(dynamicKerberosConfig.createSpnegoEntryPoint())
                        .defaultAuthenticationEntryPointFor(jwtAuthenticationEntryPoint,
                                request -> request.getRequestURI().startsWith("/api/"))
                )
                .authorizeHttpRequests(auth -> auth
                        // FIX: Removed dashboard URLs from permitAll()
                        .requestMatchers(
                                "/", "/login", "/signup", "/error",
                                "/favicon.ico", // <-- UPDATED: ADDED THIS LINE
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
                                "/admin/sso-test-result"
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
                        // All other requests (like /dashboard) are now protected
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
                .authenticationProvider(daoAuthenticationProvider()) // Your local password provider
                .addFilterBefore(tenantIdentificationFilter, SecurityContextHolderFilter.class)

                // Correct Filter Order
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(
                        dynamicKerberosConfig.createSpnegoFilter(
                                tenantAwareAuthenticationManager(),
                                kerberosSuccessHandler
                        ),
                        JwtAuthenticationFilter.class
                );

        return http.build();
    }

    /**
     * This manager correctly routes Kerberos tokens to the Kerberos provider
     * and all other tokens (like UsernamePasswordAuthenticationToken) to the DAO provider.
     */
    @Bean
    public AuthenticationManager tenantAwareAuthenticationManager() {
        return authentication -> {

            // Check if the token is a Kerberos token
            if (authentication instanceof KerberosServiceRequestToken) {
                log.debug("Received KerberosServiceRequestToken, attempting Kerberos authentication...");
                KerberosServiceAuthenticationProvider kerberosProvider =
                        dynamicKerberosConfig.createKerberosProvider();

                if (kerberosProvider != null) {
                    return kerberosProvider.authenticate(authentication);
                } else {
                    log.warn("Received Kerberos token, but no Kerberos provider is configured for this tenant.");
                    return null;
                }
            }

            // Fallback for password logins
            log.debug("Token is not Kerberos, attempting with DAO provider.");
            return daoAuthenticationProvider().authenticate(authentication);
        };
    }

    /**
     * This bean provides the fallback for local username/password authentication.
     */
    @Bean
    public AuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    /**
     * Exposes the new tenant-aware manager to the Spring context.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return tenantAwareAuthenticationManager();
    }

    // ========================================
    // SUCCESS HANDLERS & OTHER BEANS
    // ========================================

    @Bean
    public AuthenticationSuccessHandler kerberosSuccessHandler(
            AuthService authService,
            JwtTokenProvider jwtTokenProvider
    ) {
        return (request, response, authentication) -> {
            HttpSession session = request.getSession();
            String testProviderId = (String) session.getAttribute("sso_test_provider_id");

            // Fix for the previous NullPointerException
            Authentication successfulAuthentication = SecurityContextHolder.getContext().getAuthentication();

            if (successfulAuthentication == null) {
                log.error("CRITICAL: Kerberos success handler called, but no Authentication found in SecurityContextHolder.");
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Authentication context is null after Kerberos success.");
                return;
            }

            // --- THIS IS THE FIX ---
            // We MUST use the lowercase name to match the JWT and DB
            String username = successfulAuthentication.getName().toLowerCase();
            // --- END FIX ---

            log.info("Kerberos authentication successful for: {}", username);

            // --- FIX for JIT Provisioning Race Condition ---
            // We must explicitly call processKerberosLogin *here*
            // to ensure the user is saved *before* the token is generated.
            User appUser = authService.processKerberosLogin(username);
            // --- END FIX ---

            // Check if this is an attribute test
            if (testProviderId != null) {
                log.info("Kerberos login is an attribute test for: {}", testProviderId);
                Map<String, String> attributes = new HashMap<>();
                attributes.put("username", username);
                attributes.put("roles", successfulAuthentication.getAuthorities().stream()
                        .map(Object::toString).collect(Collectors.joining(",")));

                if (appUser != null) {
                    attributes.put("principal (email)", appUser.getEmail());
                    attributes.put("providerId", appUser.getProviderId());
                }

                session.setAttribute("sso_test_attributes", attributes);
                response.sendRedirect("/admin/sso-test-result");
                return;
            }

            // --- Normal Login Flow ---
            // The username is already lowercase
            String accessToken = jwtTokenProvider.generateTokenFromUsername(username);

            // Redirect based on roles
            String targetUrl = "/dashboard";
            if (appUser.hasRole("ROLE_SUPER_ADMIN")) {
                targetUrl = "/super-admin/dashboard";
            } else if (appUser.hasRole("ROLE_ADMIN")) {
                targetUrl = "/admin-dashboard";
            }

            String redirectUrl = targetUrl + "?token=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
            log.info("Redirecting to {} with JWT token.", targetUrl);
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