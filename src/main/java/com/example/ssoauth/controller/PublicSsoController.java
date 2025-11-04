package com.example.ssoauth.controller;

import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.service.SsoConfigService;
import jakarta.servlet.http.HttpSession; // IMPORT
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j; // IMPORT
import org.springframework.http.HttpStatus; // IMPORT
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable; // IMPORT
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI; // IMPORT
import java.net.URLEncoder; // *** NEW IMPORT ***
import java.nio.charset.StandardCharsets; // *** NEW IMPORT ***
import java.util.List;

@RestController
@RequestMapping("/api/sso") // Public base path
@RequiredArgsConstructor
@Slf4j // IMPORT
public class PublicSsoController {

    private final SsoConfigService ssoConfigService;

    // Endpoint for login.html to fetch enabled providers
    @GetMapping("/enabled-providers")
    public ResponseEntity<List<String>> getEnabledProviders() {
        List<String> providerIds = ssoConfigService.getEnabledProviderIds();
        return ResponseEntity.ok(providerIds);
    }

    // *** --- UPDATED ENDPOINT TO START ATTRIBUTE TEST --- ***
    @GetMapping("/test-attributes/{providerId}")
    public ResponseEntity<Void> testAttributes(@PathVariable String providerId, HttpSession session) {
        log.info("Initiating attribute test for provider: {}", providerId);

        // 1. Set a flag in the session to indicate a test is in progress
        session.setAttribute("sso_test_provider_id", providerId);

        // 2. Determine the correct redirect URL (OIDC vs SAML vs JWT)
        SsoProviderConfig config = ssoConfigService.getConfigByProviderId(providerId)
                .orElseThrow(() -> new RuntimeException("Provider not found: " + providerId));

        String redirectUrl;
        switch (config.getProviderType()) {
            case OIDC:
                redirectUrl = "/oauth2/authorization/" + providerId;
                break;
            case SAML:
                redirectUrl = "/saml2/authenticate/" + providerId;
                break;
            // *** --- NEW CASE FOR JWT --- ***
            case JWT:
                try {
                    String ssoUrl = config.getJwtSsoUrl() != null ? config.getJwtSsoUrl() : "#";
                    String clientId = config.getClientId() != null ? config.getClientId() : "";
                    // Use the configured redirect URI for JWT
                    String redirectUri = config.getJwtRedirectUri() != null ? config.getJwtRedirectUri() : "";
                    String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);

                    redirectUrl = ssoUrl + "?client_id=" + clientId + "&redirect_uri=" + encodedRedirectUri;
                    log.debug("Built JWT test redirect URL: {}", redirectUrl);
                } catch (Exception e) {
                    log.error("Failed to build JWT redirect URL for test: {}", e.getMessage());
                    return ResponseEntity.badRequest().build();
                }
                break;
            // *** --- END NEW CASE --- ***
            default:
                log.warn("Attribute test not supported for provider type: {}", config.getProviderType());
                return ResponseEntity.badRequest().build();
        }

        // 3. Send a 302 Redirect to the browser to start the SSO flow
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(redirectUrl))
                .build();
    }
}