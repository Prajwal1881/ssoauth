package com.example.ssoauth.controller;

import com.example.ssoauth.dto.SsoProviderConfigDto;
import com.example.ssoauth.dto.SsoProviderConfigUpdateRequest;
import com.example.ssoauth.service.SsoConfigService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin/sso-config") // API endpoint under admin scope
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')") // Secure for admins only
public class SsoConfigController {

    private final SsoConfigService ssoConfigService;

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

    // Optional: POST to create a new configuration
    @PostMapping
    public ResponseEntity<SsoProviderConfigDto> createSsoConfig(@Valid @RequestBody SsoProviderConfigUpdateRequest createRequest) {
        SsoProviderConfigDto createdDto = ssoConfigService.createConfig(createRequest);
        // Consider returning 201 Created status with location header
        return ResponseEntity.status(201).body(createdDto);
    }
}