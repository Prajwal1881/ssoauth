package com.example.ssoauth.controller;

import com.example.ssoauth.dto.ExternalAuthRequest;
import com.example.ssoauth.dto.ExternalAuthResponse;
import com.example.ssoauth.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth/external")
@RequiredArgsConstructor
@Slf4j
public class ExternalAuthController {

    private final AuthService authService;

    @PostMapping
    public ResponseEntity<ExternalAuthResponse> authenticateExternal(@RequestBody ExternalAuthRequest request) {
        log.info("Received external auth request for user: {}", request.getUsername());
        ExternalAuthResponse response = authService.authenticateExternal(request);
        return ResponseEntity.ok(response);
    }
}
