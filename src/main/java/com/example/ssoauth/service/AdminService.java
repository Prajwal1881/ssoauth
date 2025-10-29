package com.example.ssoauth.service;

import com.example.ssoauth.dto.SignUpRequest; // Used for creating users
import com.example.ssoauth.dto.UserUpdateRequest; // Used for updating users
import com.example.ssoauth.dto.UserInfo;
import com.example.ssoauth.entity.User;
import com.example.ssoauth.exception.ResourceAlreadyExistsException;
import com.example.ssoauth.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j; // Added Slf4j for logging
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils; // Used for checking empty strings

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j // Added for logging
public class AdminService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Finds all users and maps them to UserInfo DTOs.
     * @return List of UserInfo objects.
     */
    public List<UserInfo> findAllUsers() {
        log.info("Fetching all users for admin");
        return userRepository.findAll().stream()
                .map(this::mapToUserInfo)
                .collect(Collectors.toList());
    }

    /**
     * Finds a single user by ID and maps to UserInfo DTO.
     * @param id User ID.
     * @return UserInfo object.
     * @throws EntityNotFoundException if user not found.
     */
    public UserInfo findUserById(Long id) {
        log.info("Fetching user by ID: {}", id);
        User user = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found with id: " + id));
        return mapToUserInfo(user);
    }

    /**
     * Creates a new local user based on SignUpRequest.
     * Enforces unique username/email and encodes password.
     * @param request SignUpRequest DTO (requires password).
     * @return UserInfo object of the created user.
     * @throws ResourceAlreadyExistsException if username or email exists.
     */
    @Transactional
    public UserInfo createUser(SignUpRequest request) {
        log.info("Attempting to create user with username: {}", request.getUsername());
        if (userRepository.existsByUsername(request.getUsername())) {
            log.warn("Username already exists: {}", request.getUsername());
            throw new ResourceAlreadyExistsException("Username already exists");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Email already exists: {}", request.getEmail());
            throw new ResourceAlreadyExistsException("Email already exists");
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword())) // Password encoding
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .roles(StringUtils.hasText(request.getRoles()) ? request.getRoles() : "ROLE_USER") // Use provided roles or default
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .authProvider(User.AuthProvider.LOCAL) // Admin creates local users
                .build();

        User savedUser = userRepository.save(user);
        log.info("User created successfully with ID: {}", savedUser.getId());
        return mapToUserInfo(savedUser);
    }

    /**
     * Updates an existing user based on UserUpdateRequest.
     * Password update is optional. Enforces unique username/email if changed.
     * @param id User ID to update.
     * @param request UserUpdateRequest DTO (password optional).
     * @return UserInfo object of the updated user.
     * @throws EntityNotFoundException if user not found.
     * @throws ResourceAlreadyExistsException if new username or email exists.
     */
    @Transactional
    public UserInfo updateUser(Long id, UserUpdateRequest request) {
        log.info("Attempting to update user with ID: {}", id);
        User user = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found with id: " + id));

        // Check for uniqueness only if username/email are being changed and are provided
        if (StringUtils.hasText(request.getUsername()) && !user.getUsername().equals(request.getUsername())) {
            log.debug("Username change detected for user ID {}. Checking uniqueness.", id);
            if (userRepository.existsByUsername(request.getUsername())) {
                log.warn("Update failed: New username '{}' already exists.", request.getUsername());
                throw new ResourceAlreadyExistsException("Username already exists");
            }
            user.setUsername(request.getUsername());
        }
        if (StringUtils.hasText(request.getEmail()) && !user.getEmail().equals(request.getEmail())) {
            log.debug("Email change detected for user ID {}. Checking uniqueness.", id);
            if (userRepository.existsByEmail(request.getEmail())) {
                log.warn("Update failed: New email '{}' already exists.", request.getEmail());
                throw new ResourceAlreadyExistsException("Email already exists");
            }
            user.setEmail(request.getEmail());
        }

        // Update other fields if they are present in the request
        if (StringUtils.hasText(request.getFirstName())) {
            user.setFirstName(request.getFirstName());
        }
        if (StringUtils.hasText(request.getLastName())) {
            user.setLastName(request.getLastName());
        }
        if (StringUtils.hasText(request.getRoles())) {
            // Consider adding validation for role format/values here
            log.debug("Updating roles for user ID {}: {}", id, request.getRoles());
            user.setRoles(request.getRoles());
        }

        // Handle password update only if a non-blank password is provided in the request
        if (StringUtils.hasText(request.getPassword())) {
            log.debug("Password change detected for user ID {}. Encoding new password.", id);
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        }
        // Add logic for other fields like 'enabled' if added to UserUpdateRequest DTO
        // if (request.getEnabled() != null) {
        //     user.setEnabled(request.getEnabled());
        // }

        User updatedUser = userRepository.save(user);
        log.info("User updated successfully for ID: {}", updatedUser.getId());
        return mapToUserInfo(updatedUser);
    }

    /**
     * Deletes a user by ID.
     * @param id User ID to delete.
     * @throws EntityNotFoundException if user not found.
     */
    @Transactional
    public void deleteUser(Long id) {
        log.info("Attempting to delete user with ID: {}", id);
        if (!userRepository.existsById(id)) {
            log.warn("Delete failed: User not found with ID: {}", id);
            throw new EntityNotFoundException("User not found with id: " + id);
        }
        // Consider adding a check here to prevent an admin from deleting themselves
        userRepository.deleteById(id);
        log.info("User deleted successfully with ID: {}", id);
    }

    /**
     * Helper method to map a User entity to a UserInfo DTO.
     * @param user The User entity.
     * @return UserInfo DTO.
     */
    private UserInfo mapToUserInfo(User user) {
        // Log mapping process (optional, can be verbose)
        // log.trace("Mapping User entity to UserInfo DTO for user ID: {}", user.getId());
        return UserInfo.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .authProvider(user.getAuthProvider().name())
                .roles(user.getRoles()) // Includes roles in the DTO
                .build();
    }
}