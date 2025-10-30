package com.example.ssoauth.config;

import com.example.ssoauth.security.JwtAuthenticationFilter;
import com.example.ssoauth.security.JwtAuthenticationEntryPoint;
import com.example.ssoauth.security.JwtTokenProvider;
import com.example.ssoauth.service.AuthService;
import com.example.ssoauth.entity.User;
import lombok.RequiredArgsConstructor;
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
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // Enables @PreAuthorize for method-level security
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserDetailsService userDetailsService;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    // Inject your dynamic repositories
    private final DynamicClientRegistrationRepository dynamicOidcRepository;
    private final DynamicRelyingPartyRegistrationRepository dynamicSamlRepository;

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                          AuthenticationSuccessHandler oidcLoginSuccessHandler,
                                                          AuthenticationSuccessHandler samlLoginSuccessHandler
    ) throws Exception {
        http
                // --- CSRF Configuration ---
                .csrf(AbstractHttpConfigurer::disable) // Disable CSRF as we use JWT

                // --- CORS Configuration ---
                .cors(cors -> cors.configurationSource(corsConfigurationSource())) // Apply CORS settings

                // --- Exception Handling ---
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint)) // Custom entry point for unauthorized errors

                // --- Authorization Rules ---
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers( // Public endpoints
                                "/", "/login", "/signup", "/error",
                                "/css/**", "/js/**", "/images/**", // Static assets
                                "/api/auth/**", // Local Sign-in/Sign-up API
                                "/api/sso/enabled-providers",
                                "/oauth2/**", // OIDC flow URLs
                                "/login/jwt/callback", // Manual JWT flow callback
                                "/saml2/**",
                                "/login/saml2/**",
                                "/dashboard", // User dashboard page is public
                                "/admin/dashboard" // Admin dashboard page is public
                        ).permitAll()
                        .requestMatchers( // Admin-only API endpoints
                                "/api/admin/**" // Secure only the ADMIN API
                        ).hasRole("ADMIN")
                        .requestMatchers( // Regular user API endpoints
                                "/api/user/**" // Secure USER API
                        ).hasRole("USER")
                        .anyRequest().authenticated() // Secure everything else by default
                )

                // --- OAuth2 / OIDC Login Configuration ---
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .clientRegistrationRepository(dynamicOidcRepository)
                        .successHandler(oidcLoginSuccessHandler)
                )

                // --- SAML 2.0 Login Configuration ---
                .saml2Login(saml2 -> saml2
                        .loginPage("/login")
                        .relyingPartyRegistrationRepository(dynamicSamlRepository)
                        .successHandler(samlLoginSuccessHandler)
                )

                // --- Authentication Provider ---
                .authenticationProvider(authenticationProvider())

                // --- Custom JWT Filter ---
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * This handler is only for the OIDC (OAuth2) flow.
     */
    @Bean
    public AuthenticationSuccessHandler oidcLoginSuccessHandler(
            AuthService authService,
            JwtTokenProvider jwtTokenProvider
    ) {
        return (request, response, authentication) -> {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            User appUser = authService.processOidcLogin(oidcUser); // Find/create user in DB
            String accessToken = jwtTokenProvider.generateTokenFromUsername(appUser.getUsername());

            String targetUrl = appUser.hasRole("ROLE_ADMIN") ? "/admin/dashboard" : "/dashboard";
            String redirectUrl = targetUrl + "?token=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
            response.sendRedirect(redirectUrl);
        };
    }

    /**
     * This handler is only for the SAML flow.
     */
    @Bean
    public AuthenticationSuccessHandler samlLoginSuccessHandler(
            AuthService authService,
            JwtTokenProvider jwtTokenProvider
    ) {
        return (request, response, authentication) -> {
            Saml2AuthenticatedPrincipal samlUser = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
            User appUser = authService.processSamlLogin(samlUser); // Find/create user in DB
            String accessToken = jwtTokenProvider.generateTokenFromUsername(appUser.getUsername());

            String targetUrl = appUser.hasRole("ROLE_ADMIN") ? "/admin/dashboard" : "/dashboard";
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

    // --- *** THIS IS THE CORRECTED BEAN *** ---
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // --- THIS IS THE FIX ---
        // Instead of a specific list, we use a pattern.
        // This allows any origin, which is required for SAML POST bindings.
        configuration.addAllowedOriginPattern("*");

        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true); // This is critical for SAML
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}