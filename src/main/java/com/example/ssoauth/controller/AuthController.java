package com.example.ssoauth.controller;

import com.example.ssoauth.dto.*;
import com.example.ssoauth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.example.ssoauth.service.SuperAdminService;
import com.example.ssoauth.config.TenantContext;
import com.example.ssoauth.exception.ResourceAlreadyExistsException;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final SuperAdminService superAdminService;

    @PostMapping("/public/onboard")
    public ResponseEntity<TenantDto> onboardTenantAndAdmin(
            @Valid @RequestBody TenantRegistrationRequest onboardRequest) {
        log.info("API: POST /api/auth/public/onboard - subdomain: '{}'", onboardRequest.getSubdomain());

        try {
            log.debug("Processing tenant registration request for: {}", onboardRequest.getTenantName());
            TenantDto newTenant = superAdminService.registerNewTenant(onboardRequest);

            log.info("Tenant onboarded successfully: id={}, subdomain='{}'",
                    newTenant.getId(), newTenant.getSubdomain());
            return ResponseEntity.status(HttpStatus.CREATED).body(newTenant);

        } catch (ResourceAlreadyExistsException e) {
            log.warn("Tenant onboarding failed - Resource conflict: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Tenant onboarding failed unexpectedly for subdomain: '{}'",
                    onboardRequest.getSubdomain(), e);
            throw e;
        }
    }

    @PostMapping("/signin")
    public ResponseEntity<JwtAuthResponse> signIn(@Valid @RequestBody SignInRequest signInRequest) {
        log.info("API: POST /api/auth/signin - user: '{}'", signInRequest.getUsernameOrEmail());
        Long tenantId = TenantContext.getCurrentTenant();
        log.debug("SignIn API called with tenant context: {}", tenantId);

        try {
            JwtAuthResponse response = authService.signIn(signInRequest);
            log.info("SignIn API successful for user: '{}', roles: {}",
                    signInRequest.getUsernameOrEmail(),
                    response.getUserInfo() != null ? response.getUserInfo().getRoles() : "N/A");
            return ResponseEntity.ok(response);

        } catch (org.springframework.security.authentication.BadCredentialsException e) {
            log.warn("SignIn API failed - Invalid credentials for user: '{}'", signInRequest.getUsernameOrEmail());
            throw e;
        } catch (Exception e) {
            log.error("SignIn API failed unexpectedly for user: '{}'", signInRequest.getUsernameOrEmail(), e);
            throw e;
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<JwtAuthResponse> signUp(@Valid @RequestBody SignUpRequest signUpRequest) {
        Long tenantId = TenantContext.getCurrentTenant();
        log.info("API: POST /api/auth/signup - username: '{}', email: '{}', tenant: {}",
                signUpRequest.getUsername(), signUpRequest.getEmail(), tenantId);

        try {
            if (tenantId == null) {
                log.error("SignUp blocked - No tenant context (root domain signup not allowed)");
                throw new ResourceAlreadyExistsException(
                        "Public user registration is not allowed on the main domain. Please use your organization's URL.");
            }

            log.debug("Processing signup request for user: '{}'", signUpRequest.getUsername());
            JwtAuthResponse response = authService.signUp(signUpRequest);

            log.info("SignUp API successful - New user created: '{}' (ID: {}), tenant: {}",
                    signUpRequest.getUsername(),
                    response.getUserInfo() != null ? response.getUserInfo().getId() : "N/A",
                    tenantId);
            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (ResourceAlreadyExistsException e) {
            log.warn("SignUp API failed - Duplicate resource: {} for user: '{}'",
                    e.getMessage(), signUpRequest.getUsername());
            throw e;
        } catch (Exception e) {
            log.error("SignUp API failed unexpectedly for user: '{}', tenant: {}",
                    signUpRequest.getUsername(), tenantId, e);
            throw e;
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse> logout() {
        log.info("API: POST /api/auth/logout");

        try {
            log.debug("Processing logout request");
            ApiResponse response = ApiResponse.builder()
                    .success(true)
                    .message("Logged out successfully")
                    .build();
            log.debug("Logout API completed successfully");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Logout API failed unexpectedly", e);
            throw e;
        }
    }

    @GetMapping("/validate")
    public ResponseEntity<ApiResponse> validateToken() {
        log.debug("API: GET /api/auth/validate");

        try {
            ApiResponse response = ApiResponse.builder()
                    .success(true)
                    .message("Token is valid")
                    .build();
            log.debug("Token validation successful");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Token validation API failed unexpectedly", e);
            throw e;
        }
    }
}