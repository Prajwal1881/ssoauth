package com.example.ssoauth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserUpdateRequest {

    // Keep validation for fields that should still be validated on update
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;

    @Email(message = "Email should be valid")
    @Size(max = 100)
    private String email;

    // Password is optional for updates
    @Size(min = 6, max = 100, message = "New password must be at least 6 characters if provided")
    private String password; // No @NotBlank

    private String firstName;

    private String lastName;

    // Roles might be updated
    private String roles;

    // You could add other updatable fields like 'enabled' here
    // private Boolean enabled;
}