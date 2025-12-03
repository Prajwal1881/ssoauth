package com.example.ssoauth.controller;

import com.example.ssoauth.dto.LdapUser;
import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.entity.User;
import com.example.ssoauth.exception.SSOAuthenticationException;
import com.example.ssoauth.security.JwtTokenProvider;
import com.example.ssoauth.service.AuthService;
import com.example.ssoauth.service.LdapService;
import com.example.ssoauth.service.SsoConfigService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Controller
@RequiredArgsConstructor
@Slf4j
public class AdAuthController {

    private final SsoConfigService ssoConfigService;
    private final LdapService ldapService;
    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;

    @GetMapping("/login/ad/{providerId}")
    public String showAdLoginPage(@PathVariable String providerId, Model model) {
        // Verify config exists and is enabled
        SsoProviderConfig config = ssoConfigService.getConfigByProviderId(providerId)
                .orElseThrow(() -> new SSOAuthenticationException("Provider not found: " + providerId));

        if (!config.isEnabled()) {
            return "redirect:/login?error=provider_disabled";
        }

        model.addAttribute("providerId", providerId);
        model.addAttribute("displayName", config.getDisplayName());
        return "ad-login";
    }

    @PostMapping("/auth/ad/login")
    public String processAdLogin(
            @RequestParam String providerId,
            @RequestParam String username,
            @RequestParam String password,
            RedirectAttributes redirectAttributes) {

        try {
            // 1. Fetch Config
            SsoProviderConfig config = ssoConfigService.getConfigByProviderId(providerId)
                    .orElseThrow(() -> new SSOAuthenticationException("Provider not found"));

            // 2. Authenticate against AD
            LdapUser ldapUser = ldapService.authenticate(config, username, password);
            log.info("LDAP Authentication successful for user: {}", ldapUser.getUsername());

            // 3. User Sync (Create or Update in local DB)
            // We reuse the existing powerful SSO processing method from AuthService
            User user = authService.processSsoLogin(
                    ldapUser.getUsername(),
                    ldapUser.getEmail(),
                    ldapUser.getFirstName(),
                    ldapUser.getLastName(),
                    ldapUser.getDn(), // Use DN as the unique Provider ID
                    User.AuthProvider.AD_LDAP, // <-- The enum we added in Step 1
                    providerId
            );

            // 4. Generate JWT Token
            String accessToken = jwtTokenProvider.generateTokenFromUsername(user.getUsername());

            // 5. Redirect to Dashboard
            String targetUrl = "/dashboard";
            if (user.hasRole("ROLE_SUPER_ADMIN")) {
                targetUrl = "/super-admin/dashboard";
            } else if (user.hasRole("ROLE_ADMIN")) {
                targetUrl = "/admin/dashboard";
            }

            return "redirect:" + targetUrl + "?token=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8);

        } catch (SSOAuthenticationException | IllegalArgumentException e) {
            log.warn("AD Login Failed: {}", e.getMessage());
            redirectAttributes.addFlashAttribute("error", e.getMessage());
            return "redirect:/login/ad/" + providerId;
        } catch (Exception e) {
            log.error("Unexpected error during AD login", e);
            redirectAttributes.addFlashAttribute("error", "An unexpected error occurred.");
            return "redirect:/login/ad/" + providerId;
        }
    }
}