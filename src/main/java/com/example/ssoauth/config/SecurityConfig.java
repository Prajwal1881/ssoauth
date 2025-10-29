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

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                          AuthenticationSuccessHandler oidcLoginSuccessHandler) throws Exception {
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
                                "/api/sso/enabled-providers", // <<<--- ADDED: Endpoint for login page JS
                                "/oauth2/**", // OIDC flow URLs
                                "/login/jwt/callback", // Manual JWT flow callback
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
                        .loginPage("/login") // Where to redirect if OIDC login is needed
                        .successHandler(oidcLoginSuccessHandler) // Custom handler after successful OIDC login
                )

                // --- Authentication Provider ---
                // Configures the DaoAuthenticationProvider for local username/password checks
                .authenticationProvider(authenticationProvider())

                // --- Custom JWT Filter ---
                // Add our custom filter to process JWTs from Authorization headers
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * This handler is only for the OIDC (OAuth2) flow.
     * Checks user role for redirect destination.
     */
    @Bean
    public AuthenticationSuccessHandler oidcLoginSuccessHandler(
            AuthService authService,
            JwtTokenProvider jwtTokenProvider
    ) {
        return (request, response, authentication) -> {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            User appUser = authService.processOidcLogin(oidcUser); // Find/create user in DB
            String accessToken = jwtTokenProvider.generateTokenFromUsername(appUser.getUsername()); // Create local JWT

            // Check for admin role
            String targetUrl = "/dashboard"; // Default to user dashboard
            if (appUser.hasRole("ROLE_ADMIN")) {
                targetUrl = "/admin/dashboard"; // Redirect admins to admin dashboard
            }

            String redirectUrl = targetUrl + "?token=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8); // Redirect to UI with token
            response.sendRedirect(redirectUrl);
        };
    }

    // --- Local Authentication Beans ---
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        // This provider handles the username/password authentication against your database
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService); // Tells it how to load user details
        authProvider.setPasswordEncoder(passwordEncoder()); // Tells it how to check passwords
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        // Exposes the AuthenticationManager bean, needed by AuthService for local login
        return config.getAuthenticationManager();
    }

    // --- CORS Configuration Bean ---
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Adjust origins as needed for your frontend (if it's on a different port/domain)
        configuration.setAllowedOrigins(List.of("http://localhost:8080", "http://localhost:3000")); // Allow frontend
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*")); // Allow all headers
        configuration.setAllowCredentials(true); // Allow cookies/auth headers
        configuration.setMaxAge(3600L); // Cache preflight response for 1 hour

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // Apply CORS to all paths
        return source;
    }
}