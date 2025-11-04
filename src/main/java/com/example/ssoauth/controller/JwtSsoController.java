package com.example.ssoauth.controller;

import com.example.ssoauth.entity.User;
import com.example.ssoauth.security.JwtTokenProvider;
import com.example.ssoauth.service.AuthService;
import com.example.ssoauth.service.JwtValidatorService;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Controller
@RequiredArgsConstructor
@Slf4j
public class JwtSsoController {

    private final JwtValidatorService jwtValidatorService;
    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;

    @GetMapping("/login/jwt/callback")
    public String handleJwtCallback(
            @RequestParam(value = "id_token", required = true) String receivedToken
    ) {

        log.info("Received request on /login/jwt/callback");

        if (receivedToken == null || receivedToken.isEmpty()) {
            log.warn("JWT callback received, but 'id_token' parameter is missing or empty.");
            return "redirect:/login?error=jwt_missing";
        }

        try {
            log.debug("Received external JWT token.");
            Claims claims = jwtValidatorService.validateAndParseToken(receivedToken);
            log.info("External JWT token validated successfully. Issuer: {}, Subject: {}", claims.getIssuer(), claims.getSubject());

            // This flow has hardcoded attribute names, not "smart" finding
            String email = claims.get("email", String.class);
            String firstName = claims.get("given_name", String.class);
            String lastName = claims.get("family_name", String.class);
            String providerId = claims.getSubject();
            String issuer = claims.getIssuer();

            if (firstName == null) firstName = claims.get("firstName", String.class);
            if (lastName == null) lastName = claims.get("lastName", String.class);

            // Call the 7-argument processSsoLogin, passing 'null' for the smart-mapped username
            User user = authService.processSsoLogin(
                    null,
                    email,
                    firstName,
                    lastName,
                    providerId,
                    User.AuthProvider.SSO_JWT,
                    issuer
            );
            log.info("User processed (found or created) successfully. User ID: {}", user.getId());

            String localAccessToken = jwtTokenProvider.generateTokenFromUsername(user.getUsername());
            log.debug("Generated local access token for user: {}", user.getUsername());

            String targetUrl = "/dashboard";
            if (user.hasRole("ROLE_ADMIN")) {
                targetUrl = "/admin/dashboard";
            }

            String redirectUrl = targetUrl + "?token=" + URLEncoder.encode(localAccessToken, StandardCharsets.UTF_8);
            log.info("Redirecting to {} for user: {}", targetUrl, user.getUsername());
            return "redirect:" + redirectUrl;

        } catch (Exception e) {
            log.error("Manual JWT SSO callback failed during processing: {}", e.getMessage(), e);
            return "redirect:/login?error=jwt_invalid";
        }
    }
}