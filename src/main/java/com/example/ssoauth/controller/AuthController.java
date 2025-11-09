package com.example.ssoauth.controller;

import com.example.ssoauth.dto.*;
import com.example.ssoauth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
// NEW IMPORTS
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
// END NEW IMPORTS
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    // NEW: Inject AuthenticationManager here to break the cycle
    private final AuthenticationManager authenticationManager;

    @PostMapping("/signin")
    public ResponseEntity<JwtAuthResponse> signIn(@Valid @RequestBody SignInRequest signInRequest) {
        log.info("Sign in request received for user: {}", signInRequest.getUsernameOrEmail());

        // 1. Authenticate the user using the AuthenticationManager
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        signInRequest.getUsernameOrEmail(),
                        signInRequest.getPassword()
                )
        );

        // 2. Set security context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 3. Pass the successful authentication to AuthService to get tokens
        JwtAuthResponse response = authService.generateTokensForAuthenticatedUser(authentication);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/signup")
    public ResponseEntity<JwtAuthResponse> signUp(@Valid @RequestBody SignUpRequest signUpRequest) {
        log.info("Sign up request received for user: {}", signUpRequest.getUsername());

        // 1. Create the user
        authService.signUp(signUpRequest);

        // 2. Authenticate the new user to create a session
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        signUpRequest.getUsername(),
                        signUpRequest.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 3. Generate tokens for the new user's session
        JwtAuthResponse authenticatedResponse = authService.generateTokensForAuthenticatedUser(authentication);

        return ResponseEntity.status(HttpStatus.CREATED).body(authenticatedResponse);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse> logout() {
        log.info("Logout request received");
        ApiResponse response = ApiResponse.builder()
                .success(true)
                .message("Logged out successfully")
                .build();
        return ResponseEntity.ok(response);
    }

    @GetMapping("/validate")
    public ResponseEntity<ApiResponse> validateToken() {
        ApiResponse response = ApiResponse.builder()
                .success(true)
                .message("Token is valid")
                .build();
        return ResponseEntity.ok(response);
    }
}