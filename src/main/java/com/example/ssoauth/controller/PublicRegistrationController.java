package com.example.ssoauth.controller;

import com.example.ssoauth.dto.ApiResponse;
import com.example.ssoauth.dto.TenantDto;
import com.example.ssoauth.dto.TenantRegistrationRequest;
import com.example.ssoauth.repository.TenantRepository;
import com.example.ssoauth.service.SuperAdminService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/public")
@RequiredArgsConstructor
public class PublicRegistrationController {

    private final SuperAdminService superAdminService;
    private final TenantRepository tenantRepository;

    @PostMapping("/register-tenant")
    public ResponseEntity<ApiResponse> registerTenant(@Valid @RequestBody TenantRegistrationRequest request) {
        TenantDto tenant = superAdminService.registerNewTenant(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.builder()
                .success(true)
                .message("Organization registered successfully")
                .data(tenant)
                .build());
    }

    @GetMapping("/check-subdomain")
    public ResponseEntity<Map<String, Boolean>> checkSubdomain(@RequestParam String subdomain) {
        boolean exists = tenantRepository.findBySubdomain(subdomain.toLowerCase().trim()).isPresent();
        // Return true if available (does not exist)
        return ResponseEntity.ok(Map.of("available", !exists));
    }
}