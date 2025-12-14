package com.example.ssoauth.config;

import com.example.ssoauth.exception.SSOAuthenticationException;
import com.example.ssoauth.security.JwtAuthenticationFilter;
import com.example.ssoauth.security.JwtAuthenticationEntryPoint;
import com.example.ssoauth.security.JwtTokenProvider;
import com.example.ssoauth.service.AuthService;
import com.example.ssoauth.entity.User;
import com.example.ssoauth.security.CustomAuthenticationFailureHandler; // Import the new handler
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
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter; // <-- NEW IMPORT
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
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
    private final CustomAuthenticationFailureHandler failureHandler; // Inject the handler

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                          AuthenticationSuccessHandler oidcLoginSuccessHandler,
                                                          AuthenticationSuccessHandler samlLoginSuccessHandler
    ) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint))

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/login", "/signup", "/error", "/register",
                                "/css/**", "/js/**", "/images/**",
                                "/api/auth/**",
                                "/api/sso/enabled-providers",
                                "/api/public/**",
                                "/api/sso/test-attributes/**",
                                "/oauth2/**",
                                "/login/oauth2/**",
                                "/login/jwt/callback**",
                                "/saml2/**",
                                "/login/saml2/**",
                                "/login/ad/**",  // The login page
                                "/auth/ad/**",   // The login form submission
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
                        .failureHandler(failureHandler) // <--- ADD THIS LINE
                )
                .saml2Login(saml2 -> saml2
                        .loginPage("/login")
                        .relyingPartyRegistrationRepository(dynamicSamlRepository)
                        .successHandler(samlLoginSuccessHandler)
                )
                .authenticationProvider(authenticationProvider())
                // --- THIS IS THE FIX ---
                // Move the Tenant filter to run *before* all other security filters,
                // including the SAML and OIDC filters.
                .addFilterBefore(tenantIdentificationFilter, SecurityContextHolderFilter.class)
                // --- END FIX ---
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * UPDATED: This handler now checks for test mode and redirects to the correct dashboard.
     */
    @Bean
    public AuthenticationSuccessHandler oidcLoginSuccessHandler(
            AuthService authService,
            JwtTokenProvider jwtTokenProvider
    ) {
        return (request, response, authentication) -> {
            HttpSession session = request.getSession();
            String testProviderId = (String) session.getAttribute("sso_test_provider_id");

            // ✅ FIX: Extract registrationId from OAuth2AuthenticationToken
            String registrationId = null;
            OidcUser oidcUser = null;

            if (authentication instanceof OAuth2AuthenticationToken) {
                OAuth2AuthenticationToken oauth2Token = (OAuth2AuthenticationToken) authentication;
                registrationId = oauth2Token.getAuthorizedClientRegistrationId();
                oidcUser = (OidcUser) oauth2Token.getPrincipal();

                log.info("OIDC callback received for registrationId: {}", registrationId);
            } else {
                log.error("Authentication is not OAuth2AuthenticationToken: {}",
                        authentication.getClass().getName());
                throw new SSOAuthenticationException("Invalid authentication type for OIDC");
            }

            // Check if this is an attribute test
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

            // --- Normal Login Flow ---
            // ✅ Pass registrationId explicitly
            User appUser = authService.processOidcLogin(oidcUser, registrationId);
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

    /**
     * UPDATED: This handler now checks for test mode and redirects to the correct dashboard.
     */
    @Bean
    public AuthenticationSuccessHandler samlLoginSuccessHandler(
            AuthService authService,
            JwtTokenProvider jwtTokenProvider
    ) {
        return (request, response, authentication) -> {
            HttpSession session = request.getSession();
            String testProviderId = (String) session.getAttribute("sso_test_provider_id");
            Saml2AuthenticatedPrincipal samlUser = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();

            // Check if this is an attribute test
            if (testProviderId != null && testProviderId.equals(samlUser.getRelyingPartyRegistrationId())) {
                log.info("SAML login is an attribute test for: {}", testProviderId);
                Map<String, String> attributes = new HashMap<>();
                attributes.put("NameID", samlUser.getName()); // Add NameID
                samlUser.getAttributes().forEach((key, value) -> {
                    String aValue = value.stream()
                            .map(Object::toString)
                            .collect(Collectors.joining(", "));
                    attributes.put(key, aValue);
                });

                session.setAttribute("sso_test_attributes", attributes);
                response.sendRedirect("/admin/sso-test-result");
                return; // Stop processing
            }

            // --- Normal Login Flow ---
            User appUser = authService.processSamlLogin(samlUser);
            String accessToken = jwtTokenProvider.generateTokenFromUsername(appUser.getUsername());

            // NEW: Redirect based on role
            String targetUrl = "/dashboard"; // Default for ROLE_USER
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
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
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