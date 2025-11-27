package com.example.ssoauth.controller;

// REMOVED: Unused imports
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.util.StringUtils;
import com.example.ssoauth.config.TenantContext;

import java.util.Map;

@Controller
@RequiredArgsConstructor
public class WebController {

    // REMOVED: SsoConfigService

    @GetMapping("/")
    public String home() {
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String loginPage(Model model) {
        // Check if we are on a tenant subdomain
        boolean isTenant = TenantContext.getCurrentTenant() != null;

        // Pass this flag to the HTML
        model.addAttribute("isTenant", isTenant);

        return "login";
    }

    @GetMapping("/signup")
    public String signupPage() {
        // Check if we are on a Tenant Subdomain
        if (TenantContext.getCurrentTenant() != null) {
            // We are on 'acme.localhost', serve the User Signup Page
            return "signup";
        } else {
            // We are on 'localhost' (Root), User Signup is disabled here.
            // Redirect them to create a NEW Organization instead.
            return "redirect:/register";
        }
    }

    @GetMapping("/register")
    public String registerPage() {
        return "tenant-register";
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