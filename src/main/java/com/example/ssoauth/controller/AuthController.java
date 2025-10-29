package com.example.ssoauth.controller;

import com.example.ssoauth.dto.*;
import com.example.ssoauth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signin")
    public ResponseEntity<JwtAuthResponse> signIn(@Valid @RequestBody SignInRequest signInRequest) {
        log.info("Sign in request received for user: {}", signInRequest.getUsernameOrEmail());
        JwtAuthResponse response = authService.signIn(signInRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/signup")
    public ResponseEntity<JwtAuthResponse> signUp(@Valid @RequestBody SignUpRequest signUpRequest) {
        log.info("Sign up request received for user: {}", signUpRequest.getUsername());
        JwtAuthResponse response = authService.signUp(signUpRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // !!! REMOVED ENDPOINT !!!
    // The OIDC flow is no longer triggered by a POST request to our API.
    // It's triggered by a redirect from the frontend.
    /*
    @PostMapping("/sso-login")
    public ResponseEntity<JwtAuthResponse> ssoLogin(@Valid @RequestBody SSOLoginRequest ssoLoginRequest) {
        log.info("SSO login request received");
        JwtAuthResponse response = authService.ssoLogin(ssoLoginRequest);
        return ResponseEntity.ok(response);
    }
    */

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse> logout() {
        // ... (no changes)
        log.info("Logout request received");
        ApiResponse response = ApiResponse.builder()
                .success(true)
                .message("Logged out successfully")
                .build();
        return ResponseEntity.ok(response);
    }

    @GetMapping("/validate")
    public ResponseEntity<ApiResponse> validateToken() {
        // ... (no changes)
        ApiResponse response = ApiResponse.builder()
                .success(true)
                .message("Token is valid")
                .build();
        return ResponseEntity.ok(response);
    }
}