package com.example.ssoauth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class TenantRegistrationRequest {

    // --- Tenant Details ---
    @NotBlank(message = "Company Name is required")
    private String tenantName;

    @NotBlank(message = "Subdomain is required")
    @Size(min = 3, max = 20, message = "Subdomain must be between 3 and 20 characters")
    @Pattern(regexp = "^[a-z0-9]+$", message = "Subdomain must be lowercase alphanumeric only (no spaces or symbols)")
    private String subdomain;

    // --- Admin User Details ---
    @NotBlank(message = "Username is required")
    private String username;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 6, message = "Password must be at least 6 characters")
    private String password;

    private String firstName;
    private String lastName;
}