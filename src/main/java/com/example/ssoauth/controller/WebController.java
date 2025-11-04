package com.example.ssoauth.controller;

import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.service.SsoConfigService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.util.StringUtils;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

@Controller
@RequiredArgsConstructor
public class WebController {

    private final SsoConfigService ssoConfigService;

    @GetMapping("/")
    public String home() {
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String loginPage(Model model) {
        Optional<SsoProviderConfig> jwtConfigOpt = ssoConfigService.getConfigByProviderId("jwt_miniorange");

        if (jwtConfigOpt.isPresent() && jwtConfigOpt.get().isEnabled()) {
            SsoProviderConfig jwtConfig = jwtConfigOpt.get();
            String redirectUri = jwtConfig.getJwtRedirectUri() != null ? jwtConfig.getJwtRedirectUri() : "";
            String clientId = jwtConfig.getClientId() != null ? jwtConfig.getClientId() : "";
            String ssoUrl = jwtConfig.getJwtSsoUrl() != null ? jwtConfig.getJwtSsoUrl() : "#";

            String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
            String fullJwtSsoUrl = ssoUrl + "?client_id=" + clientId + "&redirect_uri=" + encodedRedirectUri;

            model.addAttribute("jwtSsoUrl", fullJwtSsoUrl);
        } else {
            model.addAttribute("jwtSsoUrl", "#");
        }

        return "login";
    }

    @GetMapping("/signup")
    public String signupPage() {
        return "signup";
    }

    @GetMapping("/dashboard")
    public String dashboard() {
        return "dashboard";
    }

    @GetMapping("/admin/dashboard")
    public String adminDashboardPage() {
        return "admin-dashboard";
    }

    // This method displays the sso-test-result.html page
    @GetMapping("/admin/sso-test-result")
    public String ssoTestResult(Model model, HttpSession session) {
        @SuppressWarnings("unchecked")
        Map<String, String> attributes = (Map<String, String>) session.getAttribute("sso_test_attributes");
        String errorMessage = (String) session.getAttribute("sso_test_error");

        if (attributes != null && !attributes.isEmpty()) {
            model.addAttribute("success", true);
            model.addAttribute("attributes", attributes);
            model.addAttribute("email", attributes.getOrDefault("email", attributes.getOrDefault("NameID", "N/A")));
        } else {
            model.addAttribute("success", false);
            model.addAttribute("errorMessage", StringUtils.hasText(errorMessage) ? errorMessage : "No attributes were found in the session.");
        }

        // Clear the session attributes so they aren't reused
        session.removeAttribute("sso_test_attributes");
        session.removeAttribute("sso_test_error");
        session.removeAttribute("sso_test_provider_id");

        return "sso-test-result"; // Renders sso-test-result.html
    }
}