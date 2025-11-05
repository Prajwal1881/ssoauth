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
public class BrandingRequestDto {

    @NotBlank(message = "Subdomain is required")
    @Size(min = 3, max = 50, message = "Subdomain must be between 3 and 50 characters")
    @Pattern(regexp = "^[a-z0-9]+(?:-[a-z0-9]+)*$", message = "Subdomain must be lowercase alphanumeric with hyphens (e.g., 'acme-corp')")
    private String subdomain;

    private String brandingLogoUrl;

    /**
     * FIX: The regex pattern does not allow an empty string.
     * We modify it to explicitly allow an optional hex code or blank/null.
     * The simplest fix is often to clear any provided empty string in the service.
     * However, let's allow it to be blank at the DTO level if possible.
     * Since this is a @Pattern on a String, let's keep the DTO as-is and fix the service logic.
     * (The error in the image suggests a non-empty, invalid string was submitted: "##FF6600" is invalid, but "#FF6600" is valid.)
     */
    @Pattern(regexp = "^$|^#([a-fA-F0-9]{6}|[a-fA-F0-9]{3})$", message = "Color must be a valid hex code (e.g., #FF6600)")
    private String brandingPrimaryColor;
}