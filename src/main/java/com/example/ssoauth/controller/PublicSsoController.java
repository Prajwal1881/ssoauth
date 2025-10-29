package com.example.ssoauth.controller;

import com.example.ssoauth.service.SsoConfigService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/sso") // Public base path
@RequiredArgsConstructor
public class PublicSsoController {

    private final SsoConfigService ssoConfigService;

    // Endpoint for login.html to fetch enabled providers
    @GetMapping("/enabled-providers")
    public ResponseEntity<List<String>> getEnabledProviders() {
        List<String> providerIds = ssoConfigService.getEnabledProviderIds();
        return ResponseEntity.ok(providerIds);
    }
}