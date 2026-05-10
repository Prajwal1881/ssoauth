package com.example.ssoauth.controller;

import com.example.ssoauth.config.TenantContext;
import com.example.ssoauth.dto.ApiResponse;
import com.example.ssoauth.dto.TenantDto;
import com.example.ssoauth.dto.TenantRegistrationRequest;
import com.example.ssoauth.entity.Tenant;
import com.example.ssoauth.repository.TenantRepository;
import com.example.ssoauth.service.SuperAdminService;
import com.example.ssoauth.service.storage.StorageService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/public")
@RequiredArgsConstructor
public class PublicRegistrationController {

    private final SuperAdminService superAdminService;
    private final TenantRepository tenantRepository;
    private final StorageService storageService;

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
        return ResponseEntity.ok(Map.of("available", !exists));
    }

    @GetMapping("/branding")
    public ResponseEntity<Map<String, String>> getPublicBranding() {
        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) {
            return ResponseEntity.ok(Map.of());
        }
        Optional<Tenant> tenantOpt = tenantRepository.findById(tenantId);
        if (tenantOpt.isEmpty()) {
            return ResponseEntity.ok(Map.of());
        }
        Tenant tenant = tenantOpt.get();
        Map<String, String> branding = Map.ofEntries(
                Map.entry("tenantName", tenant.getName() != null ? tenant.getName() : ""),
                Map.entry("brandingLogoUrl", tenant.getBrandingLogoUrl() != null ? tenant.getBrandingLogoUrl() : ""),
                Map.entry("brandingPrimaryColor", tenant.getBrandingPrimaryColor() != null ? tenant.getBrandingPrimaryColor() : ""),
                Map.entry("logoFileUrl", tenant.getLogoPath() != null ? storageService.buildUrl(tenant.getLogoPath()) : ""),
                Map.entry("faviconUrl", tenant.getFaviconPath() != null ? storageService.buildUrl(tenant.getFaviconPath()) : "")
        );
        return ResponseEntity.ok(branding);
    }
}