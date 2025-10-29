package com.example.ssoauth.controller;

import com.example.ssoauth.dto.ApiResponse;
import com.example.ssoauth.dto.SignUpRequest; // Used for creating users
import com.example.ssoauth.dto.UserUpdateRequest; // Used for updating users
import com.example.ssoauth.dto.UserInfo;
import com.example.ssoauth.service.AdminService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST Controller for Admin-specific operations on users.
 * All endpoints require the user to have the 'ROLE_ADMIN'.
 */
@RestController // Handles REST API requests
@RequestMapping("/api/admin") // Base path for all admin API endpoints
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')") // Secures all methods in this controller
public class AdminController {

    private final AdminService adminService; // Service layer for admin logic

    /**
     * Retrieves a list of all users.
     * Accessible only by admins.
     * Mapped to GET /api/admin/users
     *
     * @return ResponseEntity containing a list of UserInfo objects.
     */
    @GetMapping("/users")
    public ResponseEntity<List<UserInfo>> getAllUsers() {
        List<UserInfo> users = adminService.findAllUsers();
        return ResponseEntity.ok(users);
    }

    /**
     * Creates a new user (typically local).
     * Accessible only by admins. Uses SignUpRequest DTO.
     * Mapped to POST /api/admin/users
     *
     * @param signUpRequest DTO containing new user details (requires password).
     * @return ResponseEntity containing the created UserInfo object.
     */
    @PostMapping("/users")
    public ResponseEntity<UserInfo> createUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        // Assumes AdminService handles password encoding and setting default roles
        UserInfo newUser = adminService.createUser(signUpRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(newUser);
    }

    /**
     * Retrieves a specific user by their ID.
     * Accessible only by admins.
     * Mapped to GET /api/admin/users/{id}
     *
     * @param id The ID of the user to retrieve.
     * @return ResponseEntity containing the UserInfo object.
     */
    @GetMapping("/users/{id}")
    public ResponseEntity<UserInfo> getUserById(@PathVariable Long id) {
        UserInfo user = adminService.findUserById(id);
        return ResponseEntity.ok(user);
    }

    /**
     * Updates an existing user.
     * Accessible only by admins. Uses UserUpdateRequest DTO (password optional).
     * Mapped to PUT /api/admin/users/{id}
     *
     * @param id            The ID of the user to update.
     * @param updateRequest DTO containing updated user details (password is optional).
     * @return ResponseEntity containing the updated UserInfo object.
     */
    @PutMapping("/users/{id}")
    public ResponseEntity<UserInfo> updateUser(@PathVariable Long id,
                                               @Valid @RequestBody UserUpdateRequest updateRequest) {
        // Pass the specific UserUpdateRequest DTO to the service
        UserInfo updatedUser = adminService.updateUser(id, updateRequest);
        return ResponseEntity.ok(updatedUser);
    }

    /**
     * Deletes a user by their ID.
     * Accessible only by admins.
     * Mapped to DELETE /api/admin/users/{id}
     *
     * @param id The ID of the user to delete.
     * @return ResponseEntity containing a success message.
     */
    @DeleteMapping("/users/{id}")
    public ResponseEntity<ApiResponse> deleteUser(@PathVariable Long id) {
        adminService.deleteUser(id);
        ApiResponse response = ApiResponse.builder()
                .success(true)
                .message("User deleted successfully")
                .build();
        return ResponseEntity.ok(response);
    }
}