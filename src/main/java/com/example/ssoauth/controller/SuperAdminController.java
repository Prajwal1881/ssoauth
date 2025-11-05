package com.example.ssoauth.controller;

import com.example.ssoauth.dto.SignUpRequest;
import com.example.ssoauth.dto.TenantDetailDto; // UPDATED DTO
import com.example.ssoauth.dto.TenantDto;
import com.example.ssoauth.dto.UserInfo;
import com.example.ssoauth.service.SuperAdminService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/super-admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('SUPER_ADMIN')")
public class SuperAdminController {

    private final SuperAdminService superAdminService;

    @PostMapping("/tenants")
    public ResponseEntity<TenantDto> createTenant(@Valid @RequestBody TenantDto tenantDto) {
        TenantDto newTenant = superAdminService.createTenant(tenantDto);
        return ResponseEntity.status(HttpStatus.CREATED).body(newTenant);
    }

    /**
     * UPDATED: This endpoint now returns the list with details (user count, etc.)
     */
    @GetMapping("/tenants")
    public ResponseEntity<List<TenantDetailDto>> getAllTenants() {
        return ResponseEntity.ok(superAdminService.getAllTenantsWithDetails());
    }

    @GetMapping("/tenants/{id}")
    public ResponseEntity<TenantDto> getTenantById(@PathVariable Long id) {
        return ResponseEntity.ok(superAdminService.getTenantById(id));
    }

    @PutMapping("/tenants/{id}")
    public ResponseEntity<TenantDto> updateTenant(@PathVariable Long id, @Valid @RequestBody TenantDto tenantDto) {
        TenantDto updatedTenant = superAdminService.updateTenant(id, tenantDto);
        return ResponseEntity.ok(updatedTenant);
    }

    @PostMapping("/tenants/{tenantId}/admin")
    public ResponseEntity<UserInfo> onboardTenantAdmin(@PathVariable Long tenantId, @Valid @RequestBody SignUpRequest signUpRequest) {
        UserInfo adminUser = superAdminService.onboardTenantAdmin(tenantId, signUpRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(adminUser);
    }
}