package com.example.ssoauth.controller;

import com.example.ssoauth.entity.SsoProviderConfig; // NEW IMPORT
import com.example.ssoauth.entity.SsoProviderType; // NEW IMPORT
import com.example.ssoauth.entity.User;
import com.example.ssoauth.exception.SSOAuthenticationException; // NEW IMPORT
import com.example.ssoauth.security.JwtTokenProvider;
import com.example.ssoauth.service.AuthService;
import com.example.ssoauth.service.JwtValidatorService;
import com.example.ssoauth.service.SsoConfigService; // NEW IMPORT
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
@RequiredArgsConstructor
@Slf4j
public class JwtSsoController {

    private final JwtValidatorService jwtValidatorService;
    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;
    private final SsoConfigService ssoConfigService; // NEWLY INJECTED

    @GetMapping("/login/jwt/callback")
    public String handleJwtCallback(
            @RequestParam(value = "id_token", required = true) String receivedToken,
            HttpSession session
    ) {

        log.info("Received request on /login/jwt/callback");
        String testProviderId = (String) session.getAttribute("sso_test_provider_id");

        if (receivedToken == null || receivedToken.isEmpty()) {
            log.warn("JWT callback received, but 'id_token' parameter is missing or empty.");
            return handleJwtError("IdP response missing 'id_token' parameter.", session, testProviderId);
        }

        try {
            log.debug("Received external JWT token. Checking for test mode...");

            // --- FIX: Dynamically load JWT config from DB ---
            // SsoConfigService is tenant-aware thanks to Phase 1 fixes.
            // If this is a test, testProviderId is set. If normal login, it's null.
            String providerId = testProviderId;
            if (providerId == null) {
                // Not a test, find the one-and-only JWT provider for this tenant
                providerId = ssoConfigService.getAllConfigEntities().stream()
                        .filter(c -> c.getProviderType() == SsoProviderType.JWT && c.isEnabled())
                        .map(SsoProviderConfig::getProviderId)
                        .findFirst()
                        .orElseThrow(() -> new SSOAuthenticationException("No enabled JWT provider found for this tenant."));
            }

            final String finalProviderId = providerId;
            SsoProviderConfig config = ssoConfigService.getConfigByProviderId(providerId)
                    .orElseThrow(() -> new SSOAuthenticationException("JWT Config not found: " + finalProviderId));

            // --- FIX: Validate using dynamic cert and issuer from DB ---
            Claims claims = jwtValidatorService.validateAndParseToken(
                    receivedToken,
                    config.getJwtCertificate(),
                    config.getIssuerUri() // Use Issuer URI from DB
            );
            log.info("External JWT token validated successfully. Issuer: {}, Subject: {}", claims.getIssuer(), claims.getSubject());
            // --- END FIX ---

            // --- Handle Test Flow ---
            if (testProviderId != null) {
                log.info("JWT login is an attribute test for: {}", testProviderId);
                Map<String, String> attributes = claims.entrySet().stream()
                        .collect(Collectors.toMap(
                                Map.Entry::getKey,
                                entry -> entry.getValue().toString()
                        ));
                session.setAttribute("sso_test_attributes", attributes);
                log.debug("Captured {} attributes for JWT test.", attributes.size());
                return "redirect:/admin/sso-test-result";
            }
            // --- End Test Flow ---


            // --- Normal Login Flow ---
            String email = claims.get("email", String.class);
            String firstName = claims.get("given_name", String.class);
            String lastName = claims.get("family_name", String.class);
            String providerSubjectId = claims.getSubject(); // This is the IdP's unique ID for the user

            if (firstName == null) firstName = claims.get("firstName", String.class);
            if (lastName == null) lastName = claims.get("lastName", String.class);

            User user = authService.processSsoLogin(
                    null, // username (let logic find)
                    email,
                    firstName,
                    lastName,
                    providerSubjectId, // Use 'sub' as the provider-specific ID
                    User.AuthProvider.SSO_JWT,
                    config.getProviderId() // Use our internal providerId
            );
            log.info("User processed (found or created) successfully. User ID: {}", user.getId());

            String localAccessToken = jwtTokenProvider.generateTokenFromUsername(user.getUsername());
            log.debug("Generated local access token for user: {}", user.getUsername());

            // NEW: Role-based redirect
            String targetUrl = "/dashboard"; // Default for ROLE_USER
            if (user.hasRole("ROLE_SUPER_ADMIN")) {
                targetUrl = "/super-admin/dashboard";
            } else if (user.hasRole("ROLE_ADMIN")) {
                targetUrl = "/admin/dashboard";
            }

            String redirectUrl = targetUrl + "?token=" + URLEncoder.encode(localAccessToken, StandardCharsets.UTF_8);
            log.info("Redirecting to {} for user: {}", targetUrl, user.getUsername());
            return "redirect:" + redirectUrl;

        } catch (Exception e) {
            log.error("Manual JWT SSO callback failed during processing: {}", e.getMessage(), e);
            return handleJwtError("JWT Validation Failed: " + e.getMessage(), session, testProviderId);
        }
    }

    private String handleJwtError(String errorMessage, HttpSession session, String testProviderId) {
        if (testProviderId != null) {
            log.warn("JWT attribute test failed: {}", errorMessage);
            session.setAttribute("sso_test_error", errorMessage);
            return "redirect:/admin/sso-test-result";
        }
        return "redirect:/login?error=jwt_invalid";
    }
}