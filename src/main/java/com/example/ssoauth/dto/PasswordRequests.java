package com.example.ssoauth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

public class PasswordRequests {

    @Data
    public static class ChangePasswordRequest {
        @NotBlank(message = "Old password is required")
        private String oldPassword;

        @NotBlank(message = "New password is required")
        @Size(min = 6, message = "New password must be at least 6 characters")
        private String newPassword;

        @NotBlank(message = "Confirm new password is required")
        private String confirmNewPassword;
    }

    @Data
    public static class AdminResetPasswordRequest {
        @NotBlank(message = "New password is required")
        @Size(min = 6, message = "New password must be at least 6 characters")
        private String newPassword;
    }

    @Data
    public static class PublicResetPasswordRequest {
        @NotBlank(message = "Username or Email is required")
        private String usernameOrEmail;

        @NotBlank(message = "New password is required")
        @Size(min = 6, message = "New password must be at least 6 characters")
        private String newPassword;

        @NotBlank(message = "Confirm new password is required")
        private String confirmNewPassword;
    }
}
