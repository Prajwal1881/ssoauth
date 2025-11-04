package com.example.ssoauth.controller;

import com.example.ssoauth.dto.ApiResponse;
import com.example.ssoauth.dto.SsoProviderConfigDto;
import com.example.ssoauth.dto.SsoProviderConfigUpdateRequest;
import com.example.ssoauth.service.SsoConfigService;
import com.example.ssoauth.service.SsoTestService; // We need this for the static test
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin/sso-config") // This path is for ADMINS ONLY
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
@Slf4j
public class SsoConfigController {

    private final SsoConfigService ssoConfigService;
    private final SsoTestService ssoTestService; // Keep this for the static test

    // GET all configurations
    @GetMapping
    public ResponseEntity<List<SsoProviderConfigDto>> getAllSsoConfigs() {
        return ResponseEntity.ok(ssoConfigService.getAllConfigs());
    }

    // GET a single configuration by ID
    @GetMapping("/{id}")
    public ResponseEntity<SsoProviderConfigDto> getSsoConfigById(@PathVariable Long id) {
        return ResponseEntity.ok(ssoConfigService.getConfigById(id));
    }

    // UPDATE a configuration by ID
    @PutMapping("/{id}")
    public ResponseEntity<SsoProviderConfigDto> updateSsoConfig(@PathVariable Long id,
                                                                @Valid @RequestBody SsoProviderConfigUpdateRequest updateRequest) {
        SsoProviderConfigDto updatedDto = ssoConfigService.updateConfig(id, updateRequest);
        return ResponseEntity.ok(updatedDto);
    }

    // POST to create a new configuration
    @PostMapping
    public ResponseEntity<SsoProviderConfigDto> createSsoConfig(@Valid @RequestBody SsoProviderConfigUpdateRequest createRequest) {
        SsoProviderConfigDto createdDto = ssoConfigService.createConfig(createRequest);
        return ResponseEntity.status(201).body(createdDto);
    }

    // Endpoint for the static "Test Connection" button (we'll rename the button in the UI)
    @PostMapping("/test-connection")
    public ResponseEntity<ApiResponse> testSsoConnection(@RequestBody SsoProviderConfigUpdateRequest testRequest) {
        ApiResponse response = ssoTestService.testConnection(testRequest);
        if (!response.getSuccess()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        return ResponseEntity.ok(response);
    }

    // The /test-attributes endpoint is now in PublicSsoController
}