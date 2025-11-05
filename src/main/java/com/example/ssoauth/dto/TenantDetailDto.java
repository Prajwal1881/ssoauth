package com.example.ssoauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TenantDetailDto {

    private Long id;
    private String name;
    private String subdomain;
    private String brandingLogoUrl;
    private String brandingPrimaryColor;

    // --- NEW FIELDS FOR STATS ---
    private Long userCount;
    private List<String> enabledProviders; // e.g., ["OIDC", "SAML"]
}