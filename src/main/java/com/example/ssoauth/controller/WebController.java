package com.example.ssoauth.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Controller
public class WebController {

    // Properties for the manual JWT flow
    @Value("${miniorange.jwt.sso.url}")
    private String jwtSsoUrl;

    @Value("${miniorange.jwt.redirect.uri}")
    private String jwtRedirectUri;

    @Value("${miniorange.jwt.client.id}")
    private String jwtClientId;


    @GetMapping("/")
    public String home() {
        // Redirect root path to the login page
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String loginPage(Model model) {
        // Build the full URL for the manual JWT SSO button, including parameters
        String encodedRedirectUri = URLEncoder.encode(jwtRedirectUri, StandardCharsets.UTF_8);
        String fullJwtSsoUrl = jwtSsoUrl + "?client_id=" + jwtClientId + "&redirect_uri=" + encodedRedirectUri;
        // Add the URL to the model so Thymeleaf can use it in login.html
        model.addAttribute("jwtSsoUrl", fullJwtSsoUrl);
        return "login"; // Return the login template name
    }

    @GetMapping("/signup")
    public String signupPage() {
        return "signup"; // Return the signup template name
    }

    @GetMapping("/dashboard")
    public String dashboard() {
        return "dashboard"; // Return the user dashboard template name
    }

    /**
     * Maps requests for the admin dashboard page.
     * Accessible based on SecurityConfig rules (permitAll for the page itself).
     */
    @GetMapping("/admin/dashboard")
    public String adminDashboardPage() {
        return "admin-dashboard"; // Return the admin dashboard template name
    }
}