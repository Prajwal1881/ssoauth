package com.example.ssoauth.controller;

import com.example.ssoauth.config.TenantContext;
import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.entity.SsoProviderType;
import com.example.ssoauth.entity.User;
import com.example.ssoauth.security.JwtTokenProvider;
import com.example.ssoauth.service.AuthService;
import com.example.ssoauth.service.JwtValidatorService;
import com.example.ssoauth.service.SsoConfigService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Controller
@RequestMapping("/login/sso/direct")
@RequiredArgsConstructor
@Slf4j
public class IdpInitiatedSsoController {

    private final SsoConfigService ssoConfigService;
    private final JwtValidatorService jwtValidatorService;
    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;
    /**
     * Helper for IdP-Initiated OIDC.
     * Redirects the user to the standard Spring Security Authorization Endpoint
     * to start the OAuth2 handshake properly.
     * * Usage: Configure IdP "Login URL" to: https://<domain>/login/sso/initiate/<providerId>
     */
    @GetMapping("/initiate/{providerId}")
    public void initiateIdpFlow(@PathVariable String providerId, HttpServletResponse response) throws IOException {
        log.info("🚀 Initiating SSO flow for provider: {}", providerId);

        SsoProviderConfig config = ssoConfigService.getConfigByProviderId(providerId)
                .orElseThrow(() -> new RuntimeException("Provider not found"));

        if (config.getProviderType() == SsoProviderType.OIDC) {
            // Redirect to the standard Spring Security initiation endpoint
            // This ensures 'state' and 'nonce' are generated correctly.
            String authorizationEndpoint = "/oauth2/authorization/" + providerId;
            log.info("🔄 Redirecting OIDC IdP-Init request to: {}", authorizationEndpoint);
            response.sendRedirect(authorizationEndpoint);
        } else {
            // For SAML, usually the IdP handles the initiation via the metadata URL,
            // but we can redirect to the SP-initiation endpoint if needed.
            log.warn("⚠️ /initiate/ endpoint is primarily for OIDC. Check configuration for SAML/JWT.");
            response.sendRedirect("/login");
        }
    }
    /**
     * Handles IdP-Initiated flows where a token is POSTed directly to the application.
     * Supports:
     * 1. Custom JWT (signed by shared secret or cert)
     * 2. OIDC ID Token (signed by provider's OIDC key)
     */
    @PostMapping("direct/{providerId}")
    public String handleDirectTokenPost(
            @PathVariable String providerId,
            @RequestParam(value = "id_token", required = false) String idToken,
            @RequestParam(value = "access_token", required = false) String accessToken,
            HttpServletRequest request
    ) {
        log.info("🚀 Received Direct SSO Request. ProviderId: {}, Tenant: {}", providerId, TenantContext.getCurrentTenant());

        try {
            // 1. Fetch Configuration
            SsoProviderConfig config = ssoConfigService.getConfigByProviderId(providerId)
                    .orElseThrow(() -> new RuntimeException("Provider config not found: " + providerId));

            if (!config.isEnabled()) {
                log.warn("❌ Provider {} is disabled", providerId);
                return "redirect:/login?error=provider_disabled";
            }

            // 2. Determine Token to Validate
            String tokenToValidate = (idToken != null && !idToken.isBlank()) ? idToken : accessToken;
            if (tokenToValidate == null) {
                log.error("❌ No token found in request body (expected 'id_token' or 'access_token')");
                return "redirect:/login?error=missing_token";
            }

            Claims claims;

            // 3. Validation Strategy based on Provider Type
            if (config.getProviderType() == SsoProviderType.OIDC) {
                // --- OIDC Handler (IdP-Initiated / Implicit) ---
                log.debug("Validating OIDC ID Token for provider: {}", providerId);
                // For OIDC, we usually validate against the JWK Set URI.
                // We reuse the JwtValidatorService, assuming it handles JWK fetch or Issuer check.
                // Note: Standard OIDC 'id_token' usually requires checking 'nonce', but in IdP-initiated
                // without a prior request, we skip nonce validation or use a static configuration.

                claims = jwtValidatorService.validateAndParseToken(
                        tokenToValidate,
                        null, // Certificate not used for standard OIDC (uses JWKs usually)
                        config.getClientSecret(), // Used for HS256 or specific flows
                        config.getIssuerUri(),
                        "RS256" // OIDC usually uses RS256
                );

            } else if (config.getProviderType() == SsoProviderType.JWT) {
                // --- Custom JWT Handler ---
                log.debug("Validating Custom JWT for provider: {}", providerId);
                claims = jwtValidatorService.validateAndParseToken(
                        tokenToValidate,
                        config.getJwtCertificate(),
                        config.getClientSecret(),
                        config.getIssuerUri(),
                        config.getSignatureAlgorithm()
                );
            } else {
                log.warn("❌ Direct SSO not supported for provider type: {}", config.getProviderType());
                return "redirect:/login?error=unsupported_flow";
            }

            log.info("✅ Direct Token Validated. Subject: {}", claims.getSubject());

            // 4. Process User Login (Common Logic)
            String email = claims.get("email", String.class);
            String firstName = claims.get("given_name", String.class);
            String lastName = claims.get("family_name", String.class);

            // Fallbacks for non-standard claims
            if (firstName == null) firstName = claims.get("firstName", String.class);
            if (lastName == null) lastName = claims.get("lastName", String.class);

            User user = authService.processSsoLogin(
                    null,
                    email,
                    firstName,
                    lastName,
                    claims.getSubject(),
                    User.AuthProvider.SSO_JWT, // Or distinguish based on config type
                    providerId
            );

            // 5. Generate Application Session Token
            String localAccessToken = jwtTokenProvider.generateTokenFromUsername(user.getUsername());

            // 6. Redirect to Dashboard
            String targetUrl = user.hasRole("ROLE_ADMIN") ? "/admin/dashboard" : "/dashboard";
            if (user.hasRole("ROLE_SUPER_ADMIN")) targetUrl = "/super-admin/dashboard";

            return "redirect:" + targetUrl + "?token=" + URLEncoder.encode(localAccessToken, StandardCharsets.UTF_8);

        } catch (Exception e) {
            log.error("❌ Direct SSO Failed for provider {}: {}", providerId, e.getMessage(), e);
            return "redirect:/login?error=sso_validation_failed";
        }
    }
}