package com.example.ssoauth.config;

import com.example.ssoauth.entity.User;
import com.example.ssoauth.exception.SSOAuthenticationException;
import com.example.ssoauth.security.CustomAuthenticationFailureHandler;
import com.example.ssoauth.security.JwtAuthenticationEntryPoint;
import com.example.ssoauth.security.JwtAuthenticationFilter;
import com.example.ssoauth.security.JwtTokenProvider;
import com.example.ssoauth.service.AuthService;
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
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

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
    private final CustomAuthenticationFailureHandler failureHandler;

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
                                "/login/ad/**",
                                "/auth/ad/**",
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
                        .failureHandler(failureHandler)
                )
                .saml2Login(saml2 -> saml2
                        .loginPage("/login")
                        .relyingPartyRegistrationRepository(dynamicSamlRepository)
                        .successHandler(samlLoginSuccessHandler)
                )
                .authenticationProvider(authenticationProvider())
                // Ensure tenant context is set BEFORE any security processing
                .addFilterBefore(tenantIdentificationFilter, SecurityContextHolderFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * CRITICAL FIX FOR MULTI-TENANCY OIDC:
     * This custom factory caches decoders based on Client ID (unique per tenant)
     * instead of Registration ID (shared across tenants).
     * * Without this, Spring Security reuses the validator from the first tenant
     * that logs in (e.g., Tenant 11) for subsequent tenants (e.g., Tenant 10),
     * causing "invalid claims" errors because the audience (aud) check fails.
     */
    @Bean
    public JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory() {
        return new TenantAwareIdTokenDecoderFactory();
    }

    static class TenantAwareIdTokenDecoderFactory implements JwtDecoderFactory<ClientRegistration> {
        private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap<>();

        @Override
        public JwtDecoder createDecoder(ClientRegistration clientRegistration) {
            // Use Client ID as the cache key. This is unique per tenant config.
            String key = clientRegistration.getClientId();

            return jwtDecoders.computeIfAbsent(key, k -> {
                OidcIdTokenDecoderFactory delegate = new OidcIdTokenDecoderFactory();
                return delegate.createDecoder(clientRegistration);
            });
        }
    }

    @Bean
    public AuthenticationSuccessHandler oidcLoginSuccessHandler(
            AuthService authService,
            JwtTokenProvider jwtTokenProvider
    ) {
        return (request, response, authentication) -> {
            HttpSession session = request.getSession();
            String testProviderId = (String) session.getAttribute("sso_test_provider_id");

            String registrationId = null;
            OidcUser oidcUser = null;

            if (authentication instanceof OAuth2AuthenticationToken) {
                OAuth2AuthenticationToken oauth2Token = (OAuth2AuthenticationToken) authentication;
                registrationId = oauth2Token.getAuthorizedClientRegistrationId();
                oidcUser = (OidcUser) oauth2Token.getPrincipal();

                log.info("✅ OIDC callback SUCCESS - RegistrationId: '{}', Tenant: {}",
                        registrationId, TenantContext.getCurrentTenant());
            } else {
                log.error("❌ Authentication is not OAuth2AuthenticationToken: {}",
                        authentication.getClass().getName());
                throw new SSOAuthenticationException("Invalid authentication type for OIDC");
            }

            if (testProviderId != null) {
                String baseTestId = testProviderId;
                Long tenantId = TenantContext.getCurrentTenant();
                if (tenantId != null) {
                    String suffix = "-" + tenantId;
                    if (testProviderId.endsWith(suffix)) {
                        baseTestId = testProviderId.substring(0, testProviderId.length() - suffix.length());
                    }
                }

                if (registrationId != null && registrationId.contains(baseTestId)) {
                    log.info("🧪 OIDC login is an attribute test for: {}", testProviderId);
                    Map<String, String> attributes = new HashMap<>();
                    oidcUser.getClaims().forEach((key, value) -> {
                        attributes.put(key, value.toString());
                    });

                    session.setAttribute("sso_test_attributes", attributes);
                    response.sendRedirect("/admin/sso-test-result");
                    return;
                }
            }

            User appUser = authService.processOidcLogin(oidcUser, registrationId);
            String accessToken = jwtTokenProvider.generateTokenFromUsername(appUser.getUsername());

            String targetUrl = "/dashboard";
            if (appUser.hasRole("ROLE_SUPER_ADMIN")) {
                targetUrl = "/super-admin/dashboard";
            } else if (appUser.hasRole("ROLE_ADMIN")) {
                targetUrl = "/admin/dashboard";
            }

            String redirectUrl = targetUrl + "?token=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
            log.info("✅ OIDC login complete - Redirecting to: {}", targetUrl);
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