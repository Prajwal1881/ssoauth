package com.example.ssoauth.controller;

import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.service.SsoConfigService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
// import org.springframework.security.crypto.password.PasswordEncoder; // No longer needed
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.util.StringUtils;
// import org.springframework.web.bind.annotation.ResponseBody; // No longer needed

// import java.net.URLEncoder; // No longer needed
// import java.nio.charset.StandardCharsets; // No longer needed
import java.util.Map;
// import java.util.Optional; // No longer needed

@Controller
@RequiredArgsConstructor
public class WebController {

    // SsoConfigService is no longer needed by /login endpoint
    // private final SsoConfigService ssoConfigService;

    @GetMapping("/")
    public String home() {
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String loginPage(Model model) {
        // --- REMOVED ---
        // All the logic for finding "jwt_miniorange" and building the URL
        // is now handled by SsoConfigService and the frontend JavaScript.
        // This controller method no longer needs to do anything.
        // --- END REMOVED ---

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

    @GetMapping("/super-admin/dashboard")
    public String superAdminDashboardPage() {
        return "super-admin-dashboard";
    }

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

        session.removeAttribute("sso_test_attributes");
        session.removeAttribute("sso_test_error");
        session.removeAttribute("sso_test_provider_id");

        return "sso-test-result";
    }
}