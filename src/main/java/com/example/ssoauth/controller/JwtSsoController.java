package com.example.ssoauth.controller;

import com.example.ssoauth.entity.User;
import com.example.ssoauth.security.JwtTokenProvider;
import com.example.ssoauth.service.AuthService;
import com.example.ssoauth.service.JwtValidatorService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpSession; // *** NEW IMPORT ***
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap; // *** NEW IMPORT ***
import java.util.Map; // *** NEW IMPORT ***
import java.util.stream.Collectors; // *** NEW IMPORT ***

@Controller
@RequiredArgsConstructor
@Slf4j
public class JwtSsoController {

    private final JwtValidatorService jwtValidatorService;
    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;

    @GetMapping("/login/jwt/callback")
    public String handleJwtCallback(
            @RequestParam(value = "id_token", required = true) String receivedToken,
            HttpSession session // *** ADDED HTTPSESSION PARAMETER ***
    ) {

        log.info("Received request on /login/jwt/callback");
        String testProviderId = (String) session.getAttribute("sso_test_provider_id");

        if (receivedToken == null || receivedToken.isEmpty()) {
            log.warn("JWT callback received, but 'id_token' parameter is missing or empty.");
            // Handle test error
            if (testProviderId != null) {
                session.setAttribute("sso_test_error", "IdP response missing 'id_token' parameter.");
                return "redirect:/admin/sso-test-result";
            }
            return "redirect:/login?error=jwt_missing";
        }

        try {
            log.debug("Received external JWT token. Checking for test mode...");
            Claims claims = jwtValidatorService.validateAndParseToken(receivedToken);
            log.info("External JWT token validated successfully. Issuer: {}, Subject: {}", claims.getIssuer(), claims.getSubject());

            // *** --- NEW: HANDLE TEST FLOW --- ***
            if (testProviderId != null) {
                log.info("JWT login is an attribute test for: {}", testProviderId);

                // Convert all claims to a String map
                Map<String, String> attributes = claims.entrySet().stream()
                        .collect(Collectors.toMap(
                                Map.Entry::getKey,
                                entry -> entry.getValue().toString()
                        ));

                session.setAttribute("sso_test_attributes", attributes);
                log.debug("Captured {} attributes for JWT test.", attributes.size());
                return "redirect:/admin/sso-test-result";
            }
            // *** --- END: HANDLE TEST FLOW --- ***


            // *** --- NORMAL LOGIN FLOW (NO CHANGES) --- ***

            // This flow has hardcoded attribute names, not "smart" finding
            String email = claims.get("email", String.class);
            String firstName = claims.get("given_name", String.class);
            String lastName = claims.get("family_name", String.class);
            String providerId = claims.getSubject();
            String issuer = claims.getIssuer();

            if (firstName == null) firstName = claims.get("firstName", String.class);
            if (lastName == null) lastName = claims.get("lastName", String.class);

            // Call the 7-argument processSsoLogin, passing 'null' for the smart-mapped username
            User user = authService.processSsoLogin(
                    null,
                    email,
                    firstName,
                    lastName,
                    providerId,
                    User.AuthProvider.SSO_JWT,
                    issuer
            );
            log.info("User processed (found or created) successfully. User ID: {}", user.getId());

            String localAccessToken = jwtTokenProvider.generateTokenFromUsername(user.getUsername());
            log.debug("Generated local access token for user: {}", user.getUsername());

            String targetUrl = "/dashboard";
            if (user.hasRole("ROLE_ADMIN")) {
                targetUrl = "/admin/dashboard";
            }

            String redirectUrl = targetUrl + "?token=" + URLEncoder.encode(localAccessToken, StandardCharsets.UTF_8);
            log.info("Redirecting to {} for user: {}", targetUrl, user.getUsername());
            return "redirect:" + redirectUrl;

        } catch (Exception e) {
            log.error("Manual JWT SSO callback failed during processing: {}", e.getMessage(), e);

            // *** --- NEW: HANDLE TEST ERROR --- ***
            if (testProviderId != null) {
                log.warn("JWT attribute test failed: {}", e.getMessage());
                session.setAttribute("sso_test_error", "JWT Validation Failed: " + e.getMessage());
                return "redirect:/admin/sso-test-result";
            }
            // *** --- END: HANDLE TEST ERROR --- ***

            return "redirect:/login?error=jwt_invalid";
        }
    }
}