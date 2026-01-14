package com.example.ssoauth.controller;

import com.example.ssoauth.dto.PasswordRequests;
import com.example.ssoauth.dto.ApiResponse;
import com.example.ssoauth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/users")
@RequiredArgsConstructor
@Slf4j
public class AdminUserController {

    private final AuthService authService;

    @PostMapping("/{userId}/password/reset")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<ApiResponse> resetUserPassword(
            @PathVariable Long userId,
            @Valid @RequestBody PasswordRequests.AdminResetPasswordRequest request) {

        log.info("API: POST /api/admin/users/{}/password/reset", userId);

        try {
            authService.adminResetPassword(userId, request.getNewPassword());

            log.info("Admin reset password successful for user ID: {}", userId);

            return ResponseEntity.ok(ApiResponse.builder()
                    .success(true)
                    .message("Password reset successfully")
                    .build());

        } catch (Exception e) {
            log.error("Admin password reset failed", e);
            throw e;
        }
    }
}
