package com.example.ssoauth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TenantDto {

    private Long id;

    @NotBlank(message = "Tenant name is required")
    @Size(max = 100)
    private String name;

    @NotBlank(message = "Subdomain is required")
    @Size(min = 3, max = 50, message = "Subdomain must be between 3 and 50 characters")
    @Pattern(regexp = "^[a-z0-9]+(?:-[a-z0-9]+)*$", message = "Subdomain must be lowercase alphanumeric with hyphens")
    private String subdomain;

    private String brandingLogoUrl;

    @Pattern(regexp = "^#([a-fA-F0-9]{6}|[a-fA-F0-9]{3})$", message = "Color must be a valid hex code (e.g., #FF6600)")
    private String brandingPrimaryColor;
}