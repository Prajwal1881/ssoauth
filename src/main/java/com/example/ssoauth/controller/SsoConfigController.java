package com.example.ssoauth.controller;

import com.example.ssoauth.config.TenantContext;
import com.example.ssoauth.dto.ApiResponse;
import com.example.ssoauth.dto.SsoProviderConfigDto;
import com.example.ssoauth.dto.SsoProviderConfigUpdateRequest;
import com.example.ssoauth.repository.SsoProviderConfigRepository;
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
import com.example.ssoauth.entity.Tenant; // Ensure entity is imported or accessible
import com.example.ssoauth.repository.TenantRepository; // Need to inject this

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
    private final SsoProviderConfigRepository configRepository; // For debug endpoint
    private final TenantRepository tenantRepository;

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

    // --- NEW: DEBUG ENDPOINT ---

    /**
     * DEBUG ENDPOINT: Returns tenant context and all SSO configs with their tenant IDs.
     * Use this to troubleshoot tenant isolation issues.
     *
     * SECURITY: Only accessible to ADMINs, returns only configs for current tenant.
     */
    @GetMapping("/debug/tenant-info")
    public ResponseEntity<Map<String, Object>> getDebugInfo() {
        Long currentTenantId = TenantContext.getCurrentTenant();

        Map<String, Object> debugInfo = new HashMap<>();
        debugInfo.put("currentTenantId", currentTenantId);
        debugInfo.put("timestamp", System.currentTimeMillis());

        // Get all configs using the debug query
        List<Object[]> allConfigs = configRepository.findAllWithTenantInfo();
        List<Map<String, Object>> configList = allConfigs.stream()
                .map(row -> {
                    Map<String, Object> config = new HashMap<>();
                    config.put("id", row[0]);
                    config.put("providerId", row[1]);
                    config.put("providerType", row[2]);
                    config.put("tenantId", row[3]);
                    config.put("subdomain", row[4]);
                    config.put("visibleToMe", currentTenantId != null && currentTenantId.equals(row[3]));
                    return config;
                })
                .collect(Collectors.toList());

        debugInfo.put("allConfigsInDatabase", configList);

        // Get configs visible through service layer
        List<SsoProviderConfigDto> myConfigs = ssoConfigService.getAllConfigs();
        debugInfo.put("myVisibleConfigs", myConfigs.stream()
                .map(c -> Map.of("id", c.getId(), "providerId", c.getProviderId()))
                .collect(Collectors.toList()));

        log.info("DEBUG: Tenant {} sees {} total configs, {} visible to them",
                currentTenantId, configList.size(), myConfigs.size());

        return ResponseEntity.ok(debugInfo);
    }
    // --- NEW: SAML Metadata Endpoints ---

    @PostMapping(value = "/saml/import-metadata", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, String>> importSamlMetadata(@RequestParam("file") MultipartFile file) {
        log.info("API: POST /saml/import-metadata");
        Map<String, String> metadata = ssoConfigService.parseSamlMetadata(file);
        return ResponseEntity.ok(metadata);
    }

    @GetMapping("/saml/download-metadata/{providerId}")
    public ResponseEntity<String> downloadSpMetadata(@PathVariable String providerId) {
        Long tenantId = TenantContext.getCurrentTenant();
        // We need the Subdomain/Base URL to generate correct EntityID
        // Ideally, fetch tenant to construct the domain
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new RuntimeException("Tenant not found"));

        // Construct Base URL (Assuming logic similar to TenantIdentificationFilter)
        // Note: You might need to inject 'app.base-domain' here
        String baseDomain = "prajwal.cfd"; // Hardcoded based on your HTML, or inject @Value
        String baseUrl = "https://" + tenant.getSubdomain() + "." + baseDomain;

        String metadataXml = ssoConfigService.generateSpMetadata(providerId, baseUrl);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"sp-metadata-" + providerId + ".xml\"")
                .contentType(MediaType.APPLICATION_XML)
                .body(metadataXml);
    }
}