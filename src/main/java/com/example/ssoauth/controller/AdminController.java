package com.example.ssoauth.controller;

import com.example.ssoauth.dto.ApiResponse;
import com.example.ssoauth.dto.BrandingRequestDto;
import com.example.ssoauth.dto.SignUpRequest;
import com.example.ssoauth.dto.UserUpdateRequest;
import com.example.ssoauth.dto.UserInfo;
import com.example.ssoauth.service.AdminService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

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
        BrandingRequestDto updatedBranding = adminService.updateTenantBranding(request);
        return ResponseEntity.ok(updatedBranding);
    }

    @PostMapping(value = "/branding/logo", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, String>> uploadLogo(@RequestParam("file") MultipartFile file) {
        try {
            String logoFileUrl = adminService.uploadLogo(file);
            return ResponseEntity.ok(Map.of("logoFileUrl", logoFileUrl));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Failed to upload logo: " + e.getMessage()));
        }
    }

    @PostMapping(value = "/branding/favicon", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, String>> uploadFavicon(@RequestParam("file") MultipartFile file) {
        try {
            String faviconUrl = adminService.uploadFavicon(file);
            return ResponseEntity.ok(Map.of("faviconUrl", faviconUrl));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Failed to upload favicon: " + e.getMessage()));
        }
    }

    // --- NEW Settings Endpoint ---
    @GetMapping("/settings")
    public ResponseEntity<com.example.ssoauth.dto.TenantDto> getSettings() {
        return ResponseEntity.ok(adminService.getCurrentTenantSettings());
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