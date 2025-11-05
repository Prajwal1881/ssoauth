package com.example.ssoauth.controller;

import com.example.ssoauth.dto.ApiResponse;
import com.example.ssoauth.dto.BrandingRequestDto; // NEW IMPORT
import com.example.ssoauth.dto.SignUpRequest;
import com.example.ssoauth.dto.UserUpdateRequest;
import com.example.ssoauth.dto.UserInfo;
import com.example.ssoauth.service.AdminService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final AdminService adminService;

    // --- NEW Branding Endpoints ---

    @GetMapping("/branding")
    public ResponseEntity<BrandingRequestDto> getBranding() {
        return ResponseEntity.ok(adminService.getTenantBranding());
    }

    @PutMapping("/branding")
    public ResponseEntity<BrandingRequestDto> updateBranding(@Valid @RequestBody BrandingRequestDto request) {
        // The service method handles the uniqueness check
        BrandingRequestDto updatedBranding = adminService.updateTenantBranding(request);
        return ResponseEntity.ok(updatedBranding);
    }

    // --- (All other User Management endpoints are unchanged) ---

    @GetMapping("/users")
    public ResponseEntity<List<UserInfo>> getAllUsers() {
        List<UserInfo> users = adminService.findAllUsers();
        return ResponseEntity.ok(users);
    }

    @PostMapping("/users")
    public ResponseEntity<UserInfo> createUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        UserInfo newUser = adminService.createUser(signUpRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(newUser);
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<UserInfo> getUserById(@PathVariable Long id) {
        UserInfo user = adminService.findUserById(id);
        return ResponseEntity.ok(user);
    }

    @PutMapping("/users/{id}")
    public ResponseEntity<UserInfo> updateUser(@PathVariable Long id,
                                               @Valid @RequestBody UserUpdateRequest updateRequest) {
        UserInfo updatedUser = adminService.updateUser(id, updateRequest);
        return ResponseEntity.ok(updatedUser);
    }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<ApiResponse> deleteUser(@PathVariable Long id) {
        adminService.deleteUser(id);
        ApiResponse response = ApiResponse.builder()
                .success(true)
                .message("User deleted successfully")
                .build();
        return ResponseEntity.ok(response);
    }
}