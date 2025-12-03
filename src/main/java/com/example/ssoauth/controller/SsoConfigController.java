package com.example.ssoauth.controller;

import com.example.ssoauth.config.TenantContext;
import com.example.ssoauth.dto.ApiResponse;
import com.example.ssoauth.dto.LdapUser;
import com.example.ssoauth.dto.SsoProviderConfigDto;
import com.example.ssoauth.dto.SsoProviderConfigUpdateRequest;
import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.entity.User;
import com.example.ssoauth.repository.SsoProviderConfigRepository;
import com.example.ssoauth.repository.TenantRepository;
import com.example.ssoauth.service.AuthService;
import com.example.ssoauth.service.LdapService;
import com.example.ssoauth.service.SsoConfigService;
import com.example.ssoauth.service.SsoTestService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.http.MediaType;
import org.springframework.http.HttpHeaders;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin/sso-config")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
@Slf4j
public class SsoConfigController {

    private final SsoConfigService ssoConfigService;
    private final SsoTestService ssoTestService;
    private final SsoProviderConfigRepository configRepository;
    private final TenantRepository tenantRepository;
    private final LdapService ldapService;
    private final AuthService authService;

    // --- CRUD Endpoints ---

    @GetMapping
    public ResponseEntity<List<SsoProviderConfigDto>> getAllSsoConfigs() {
        Long tenantId = TenantContext.getCurrentTenant();
        log.info("API: GET /api/admin/sso-config - tenantId={}", tenantId);
        return ResponseEntity.ok(ssoConfigService.getAllConfigs());
    }

    @GetMapping("/{id}")
    public ResponseEntity<SsoProviderConfigDto> getSsoConfigById(@PathVariable Long id) {
        Long tenantId = TenantContext.getCurrentTenant();
        log.info("API: GET /api/admin/sso-config/{} - tenantId={}", id, tenantId);
        return ResponseEntity.ok(ssoConfigService.getConfigById(id));
    }

    @PutMapping("/{id}")
    public ResponseEntity<SsoProviderConfigDto> updateSsoConfig(
            @PathVariable Long id,
            @Valid @RequestBody SsoProviderConfigUpdateRequest updateRequest) {
        Long tenantId = TenantContext.getCurrentTenant();
        log.info("API: PUT /api/admin/sso-config/{} - tenantId={}", id, tenantId);
        SsoProviderConfigDto updatedDto = ssoConfigService.updateConfig(id, updateRequest);
        return ResponseEntity.ok(updatedDto);
    }

    @PostMapping
    public ResponseEntity<SsoProviderConfigDto> createSsoConfig(
            @Valid @RequestBody SsoProviderConfigUpdateRequest createRequest) {
        Long tenantId = TenantContext.getCurrentTenant();
        log.info("API: POST /api/admin/sso-config - tenantId={}, providerId='{}'",
                tenantId, createRequest.getProviderId());
        SsoProviderConfigDto createdDto = ssoConfigService.createConfig(createRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdDto);
    }

    @PostMapping("/test-connection")
    public ResponseEntity<ApiResponse> testSsoConnection(
            @RequestBody SsoProviderConfigUpdateRequest testRequest) {
        log.info("API: POST /api/admin/sso-config/test-connection - providerId='{}'",
                testRequest.getProviderId());
        ApiResponse response = ssoTestService.testConnection(testRequest);
        if (!response.getSuccess()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        return ResponseEntity.ok(response);
    }

    // --- NEW: AD User Import Endpoint ---
    @PostMapping("/ad/import")
    public ResponseEntity<ApiResponse> importAdUsers(@RequestBody Map<String, String> request) {
        String providerId = request.get("providerId");
        log.info("API: POST /api/admin/sso-config/ad/import - providerId='{}'", providerId);

        try {
            // 1. Fetch Config
            SsoProviderConfig config = ssoConfigService.getConfigByProviderId(providerId)
                    .orElseThrow(() -> new RuntimeException("Provider not found: " + providerId));

            // 2. Fetch Users from AD
            List<LdapUser> adUsers = ldapService.listUsers(config);

            if (adUsers.isEmpty()) {
                return ResponseEntity.ok(ApiResponse.builder()
                        .success(true)
                        .message("Connected to AD, but no users found matching the filter.")
                        .build());
            }

            // 3. Process/Save Users (Outbound Provisioning)
            int createdOrUpdated = 0;

            for (LdapUser adUser : adUsers) {
                // authService.processSsoLogin handles creation (with random password) or updates
                authService.processSsoLogin(
                        adUser.getUsername(),
                        adUser.getEmail(),
                        adUser.getFirstName(),
                        adUser.getLastName(),
                        adUser.getDn(), // Provider ID unique key
                        User.AuthProvider.AD_LDAP,
                        providerId
                );
                createdOrUpdated++;
            }

            String msg = String.format("Sync Complete! Processed %d users from Active Directory.", createdOrUpdated);
            return ResponseEntity.ok(ApiResponse.builder().success(true).message(msg).data(createdOrUpdated).build());

        } catch (Exception e) {
            log.error("Import failed", e);
            return ResponseEntity.badRequest().body(ApiResponse.builder()
                    .success(false)
                    .message("Import Failed: " + e.getMessage())
                    .build());
        }
    }

    // --- SAML Metadata Endpoints ---

    @PostMapping(value = "/saml/import-metadata", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, String>> importSamlMetadata(@RequestParam("file") MultipartFile file) {
        log.info("API: POST /saml/import-metadata");
        Map<String, String> metadata = ssoConfigService.parseSamlMetadata(file);
        return ResponseEntity.ok(metadata);
    }

    @GetMapping("/saml/download-metadata/{providerId}")
    public ResponseEntity<String> downloadSpMetadata(@PathVariable String providerId) {
        Long tenantId = TenantContext.getCurrentTenant();
        // Ideally, fetch tenant to construct the domain
        // For now, assuming standard naming
        String metadataXml = ssoConfigService.generateSpMetadata(providerId, "https://example.prajwal.cfd"); // Replace with dynamic logic if needed

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"sp-metadata-" + providerId + ".xml\"")
                .contentType(MediaType.APPLICATION_XML)
                .body(metadataXml);
    }

    // --- DEBUG ENDPOINT ---
    @GetMapping("/debug/tenant-info")
    public ResponseEntity<Map<String, Object>> getDebugInfo() {
        Long currentTenantId = TenantContext.getCurrentTenant();
        Map<String, Object> debugInfo = new HashMap<>();
        debugInfo.put("currentTenantId", currentTenantId);
        return ResponseEntity.ok(debugInfo);
    }
}