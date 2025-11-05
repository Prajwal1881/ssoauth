package com.example.ssoauth.controller;

import com.example.ssoauth.config.TenantContext;
import com.example.ssoauth.dto.EnabledProviderDto;
import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.entity.Tenant;
import com.example.ssoauth.repository.TenantRepository;
import com.example.ssoauth.service.SsoConfigService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/sso")
@RequiredArgsConstructor
@Slf4j
public class PublicSsoController {

    private final SsoConfigService ssoConfigService;
    private final TenantRepository tenantRepository;

    @GetMapping("/enabled-providers")
    public ResponseEntity<List<EnabledProviderDto>> getEnabledProviders() {
        // This method is now correct, as SsoConfigService handles resolving
        // the String subdomain to a Long ID.
        List<EnabledProviderDto> providerDtos = ssoConfigService.getEnabledProviders();
        return ResponseEntity.ok(providerDtos);
    }

    @GetMapping("/public/branding")
    public ResponseEntity<Map<String, String>> getTenantBranding() {
        // --- FIX: Get String subdomain from context ---
        String subdomain = TenantContext.getCurrentTenant();
        if (subdomain == null) {
            // No subdomain, return empty map
            return ResponseEntity.ok(Map.of());
        }

        // Find the tenant by the String subdomain
        Optional<Tenant> tenantOpt = tenantRepository.findBySubdomain(subdomain);
        // --- END FIX ---

        if (tenantOpt.isEmpty()) {
            return ResponseEntity.ok(Map.of()); // No tenant found, return empty map
        }

        Tenant tenant = tenantOpt.get();
        Map<String, String> branding = Map.ofEntries(
                Map.entry("tenantName", tenant.getName() != null ? tenant.getName() : ""),
                Map.entry("brandingLogoUrl", tenant.getBrandingLogoUrl() != null ? tenant.getBrandingLogoUrl() : ""),
                Map.entry("brandingPrimaryColor", tenant.getBrandingPrimaryColor() != null ? tenant.getBrandingPrimaryColor() : "")
        );
        return ResponseEntity.ok(branding);
    }

    @GetMapping("/test-attributes/{providerId}")
    public ResponseEntity<Void> testAttributes(@PathVariable String providerId, HttpSession session) {

        log.info("Initiating attribute test for provider: {}", providerId);

        session.setAttribute("sso_test_provider_id", providerId);

        // This method is now correct, as SsoConfigService handles resolving
        // the String subdomain to a Long ID before finding the config.
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
            case JWT:
                try {
                    String ssoUrl = config.getJwtSsoUrl() != null ? config.getJwtSsoUrl() : "#";
                    String clientId = config.getClientId() != null ? config.getClientId() : "";
                    String redirectUri = config.getJwtRedirectUri() != null ? config.getJwtRedirectUri() : "";
                    String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);

                    redirectUrl = ssoUrl + "?client_id=" + clientId + "&redirect_uri=" + encodedRedirectUri;
                    log.debug("Built JWT test redirect URL: {}", redirectUrl);
                } catch (Exception e) {
                    log.error("Failed to build JWT redirect URL for test: {}", e.getMessage());
                    return ResponseEntity.badRequest().build();
                }
                break;
            default:
                log.warn("Attribute test not supported for provider type: {}", config.getProviderType());
                return ResponseEntity.badRequest().build();
        }

        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(redirectUrl))
                .build();
    }
}