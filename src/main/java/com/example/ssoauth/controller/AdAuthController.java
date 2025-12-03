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

            // 1. Attempt LDAP Authentication
            LdapUser ldapUser = ldapService.authenticate(config, username, password);
            log.info("LDAP Authentication successful for user: {}", ldapUser.getUsername());

            User user;
            // 2. Handle User Sync Logic
            if (Boolean.TRUE.equals(config.getLdapSyncUsers())) {
                // Sync ON: Create or Update user in local DB
                user = authService.processSsoLogin(
                        ldapUser.getUsername(),
                        ldapUser.getEmail(),
                        ldapUser.getFirstName(),
                        ldapUser.getLastName(),
                        ldapUser.getDn(),
                        User.AuthProvider.AD_LDAP,
                        providerId
                );
            } else {
                // Sync OFF: Only allow login if user exists locally
                Long tenantId = TenantContext.getCurrentTenant();
                Optional<User> localUser = userRepository.findByEmailAndTenantId(ldapUser.getEmail(), tenantId);

                if (localUser.isPresent()) {
                    user = localUser.get();
                    // Optional: Update last login even if sync is off
                    user.setLastLogin(java.time.LocalDateTime.now());
                    userRepository.save(user);
                } else {
                    log.warn("LDAP login successful but User Sync is disabled and user not found locally: {}", ldapUser.getEmail());
                    throw new SSOAuthenticationException("Login failed: User not found locally and sync is disabled.");
                }
            }

            return generateTokenAndRedirect(user);

        } catch (Exception e) {
            log.warn("AD Login Failed: {}", e.getMessage());

            // 3. Handle Fallback Authentication
            if (config != null && Boolean.TRUE.equals(config.getLdapFallbackAuth())) {
                log.info("Attempting Fallback Authentication (Local DB) for user: {}", username);
                try {
                    // Reuse the standard SignIn logic
                    SignInRequest fallbackRequest = new SignInRequest(username, password);
                    JwtAuthResponse fallbackResponse = authService.signIn(fallbackRequest);

                    // If we get here, local auth succeeded
                    log.info("Fallback Authentication successful for user: {}", username);

                    // We need to retrieve the user entity to check roles for redirect
                    // Since authService.signIn returns a DTO, we can just use the token or fetch user again.
                    // For simplicity, let's just use the DTO info to redirect
                    String accessToken = fallbackResponse.getAccessToken();
                    String targetUrl = determineRedirectUrl(fallbackResponse.getUserInfo().getRoles());

                    return "redirect:" + targetUrl + "?token=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8);

                } catch (Exception localEx) {
                    log.error("Fallback Authentication also failed: {}", localEx.getMessage());
                    // Fall through to show the original error or a generic one
                }
            }

            redirectAttributes.addFlashAttribute("error", "Authentication failed. " + e.getMessage());
            return "redirect:/login/ad/" + providerId;
        }
    }

    private String generateTokenAndRedirect(User user) {
        String accessToken = jwtTokenProvider.generateTokenFromUsername(user.getUsername());
        String targetUrl = determineRedirectUrl(user.getRoles());
        return "redirect:" + targetUrl + "?token=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
    }

    private String determineRedirectUrl(String roles) {
        if (roles.contains("ROLE_SUPER_ADMIN")) return "/super-admin/dashboard";
        if (roles.contains("ROLE_ADMIN")) return "/admin/dashboard";
        return "/dashboard";
    }
}