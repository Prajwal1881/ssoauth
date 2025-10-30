package com.example.ssoauth.controller;

import com.example.ssoauth.entity.User;
import com.example.ssoauth.security.JwtTokenProvider;
import com.example.ssoauth.service.AuthService;
import com.example.ssoauth.service.JwtValidatorService;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping; // Handles GET request from IdP redirect
import org.springframework.web.bind.annotation.RequestParam;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Controller
@RequiredArgsConstructor
@Slf4j
public class JwtSsoController {

    private final JwtValidatorService jwtValidatorService;
    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * Handles the callback from the manual miniOrange JWT SSO flow.
     * MiniOrange redirects here via GET after successful authentication,
     * including the JWT token as the 'id_token' query parameter.
     *
     * @param receivedToken The JWT token sent by MiniOrange.
     * @return A redirect string to the dashboard on success, or back to login on error.
     */
    @GetMapping("/login/jwt/callback") // Uses GET method for URL-based token delivery
    public String handleJwtCallback(
            @RequestParam(value = "id_token", required = true) String receivedToken
    ) {

        log.info("Received request on /login/jwt/callback");

        if (receivedToken == null || receivedToken.isEmpty()) {
            log.warn("JWT callback received, but 'id_token' parameter is missing or empty.");
            return "redirect:/login?error=jwt_missing";
        }

        try {
            // 1. Validate the external JWT
            log.debug("Received external JWT token.");
            Claims claims = jwtValidatorService.validateAndParseToken(receivedToken);
            log.info("External JWT token validated successfully. Issuer: {}, Subject: {}", claims.getIssuer(), claims.getSubject());

            // 2. Extract user information from the JWT claims
            String email = claims.get("email", String.class);
            String firstName = claims.get("given_name", String.class);
            String lastName = claims.get("family_name", String.class);
            String providerId = claims.getSubject();
            String issuer = claims.getIssuer(); // Get the issuer to use as registrationId

            if (firstName == null) firstName = claims.get("firstName", String.class);
            if (lastName == null) lastName = claims.get("lastName", String.class);

            // 3. Find or create the user in our local database
            // AuthService handles cache bypass and ensuring correct roles are loaded/set
            // *** THIS IS THE CORRECTED LINE ***
            User user = authService.processSsoLogin(
                    email,
                    firstName,
                    lastName,
                    providerId,
                    User.AuthProvider.SSO_JWT,
                    issuer // Pass the issuer as the 6th argument
            );
            log.info("User processed (found or created) successfully. User ID: {}", user.getId());

            // 4. Generate our *own* local JWT for our application
            String localAccessToken = jwtTokenProvider.generateTokenFromUsername(user.getUsername());
            log.debug("Generated local access token for user: {}", user.getUsername());


            // --- 5. Redirect based on role ---
            String targetUrl = "/dashboard"; // Default to user dashboard

            // Check if the user has the required admin role
            if (user.hasRole("ROLE_ADMIN")) {
                targetUrl = "/admin/dashboard";
            }

            // Perform the final redirect
            String redirectUrl = targetUrl + "?token=" + URLEncoder.encode(localAccessToken, StandardCharsets.UTF_8);
            log.info("Redirecting to {} for user: {}", targetUrl, user.getUsername());
            return "redirect:" + redirectUrl;

        } catch (Exception e) {
            // Catch any failures during validation, processing, or database interaction
            log.error("Manual JWT SSO callback failed during processing: {}", e.getMessage(), e);
            return "redirect:/login?error=jwt_invalid";
        }
    }
}