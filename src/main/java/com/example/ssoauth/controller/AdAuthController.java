package com.example.ssoauth.controller;

import com.example.ssoauth.config.TenantContext;
import com.example.ssoauth.dto.JwtAuthResponse;
import com.example.ssoauth.dto.LdapUser;
import com.example.ssoauth.dto.SignInRequest;
import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.entity.User;
import com.example.ssoauth.exception.SSOAuthenticationException;
import com.example.ssoauth.security.JwtTokenProvider;
import com.example.ssoauth.service.AuthService;
import com.example.ssoauth.service.LdapService;
import com.example.ssoauth.service.SsoConfigService;
import com.example.ssoauth.repository.UserRepository; // Needed for non-sync check
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Controller
@RequiredArgsConstructor
@Slf4j
public class AdAuthController {

    private final SsoConfigService ssoConfigService;
    private final LdapService ldapService;
    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

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

        SsoProviderConfig config = null;
        try {
            config = ssoConfigService.getConfigByProviderId(providerId)
                    .orElseThrow(() -> new SSOAuthenticationException("Provider not found"));

            // 1. Authenticate against AD (Bind Check)
            LdapUser ldapUser = ldapService.authenticate(config, username, password);
            log.info("LDAP Authentication successful for user: {}", ldapUser.getUsername());

            // 2. Perform JIT Provisioning (Create or Update)
            // We REMOVED the 'if (syncUsers)' check. Now we always provision.
            // AuthService.processSsoLogin handles "Find by Email" -> "Update" OR "Create New with Random Password"
            User user = authService.processSsoLogin(
                    ldapUser.getUsername(),
                    ldapUser.getEmail(),
                    ldapUser.getFirstName(),
                    ldapUser.getLastName(),
                    ldapUser.getDn(), // Use DN as the unique Provider ID
                    User.AuthProvider.AD_LDAP,
                    providerId
            );

            // 3. Generate Token and Redirect
            return generateTokenAndRedirect(user);

        } catch (Exception e) {
            log.warn("AD Login Failed: {}", e.getMessage());

            // 4. Handle Fallback Authentication (Try Local DB if LDAP fails)
            if (config != null && Boolean.TRUE.equals(config.getLdapFallbackAuth())) {
                log.info("Attempting Fallback Authentication (Local DB) for user: {}", username);
                try {
                    // Reuse the standard SignIn logic
                    SignInRequest fallbackRequest = new SignInRequest(username, password);
                    JwtAuthResponse fallbackResponse = authService.signIn(fallbackRequest);

                    log.info("Fallback Authentication successful for user: {}", username);

                    // Simple redirect for fallback; roles will be handled by the frontend dashboard logic or next request
                    return "redirect:/dashboard?token=" + URLEncoder.encode(fallbackResponse.getAccessToken(), StandardCharsets.UTF_8);

                } catch (Exception localEx) {
                    log.error("Fallback Authentication also failed: {}", localEx.getMessage());
                }
            }

            redirectAttributes.addFlashAttribute("error", "Authentication failed. " + e.getMessage());
            return "redirect:/login/ad/" + providerId;
        }
    }

    private String generateTokenAndRedirect(User user) {
        String accessToken = jwtTokenProvider.generateTokenFromUsername(user.getUsername());

        // Determine redirect based on role
        String targetUrl = "/dashboard";
        if (user.hasRole("ROLE_SUPER_ADMIN")) {
            targetUrl = "/super-admin/dashboard";
        } else if (user.hasRole("ROLE_ADMIN")) {
            targetUrl = "/admin/dashboard";
        }

        return "redirect:" + targetUrl + "?token=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
    }

    private String determineRedirectUrl(String roles) {
        if (roles.contains("ROLE_SUPER_ADMIN")) return "/super-admin/dashboard";
        if (roles.contains("ROLE_ADMIN")) return "/admin/dashboard";
        return "/dashboard";
    }
}