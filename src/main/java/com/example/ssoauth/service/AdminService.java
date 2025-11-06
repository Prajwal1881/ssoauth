package com.example.ssoauth.service;

import com.example.ssoauth.config.TenantContext;
import com.example.ssoauth.dto.BrandingRequestDto;
import com.example.ssoauth.dto.SignUpRequest;
import com.example.ssoauth.dto.UserUpdateRequest;
import com.example.ssoauth.dto.UserInfo;
import com.example.ssoauth.entity.Tenant;
import com.example.ssoauth.entity.User;
import com.example.ssoauth.exception.ResourceAlreadyExistsException;
import com.example.ssoauth.repository.TenantRepository;
import com.example.ssoauth.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TenantRepository tenantRepository;

    /**
     * CRITICAL FIX: Always validate tenant context before operations.
     */
    private Long getTenantIdFromContextOrFail() {
        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) {
            log.error("SECURITY VIOLATION: Admin operation attempted without tenant context");
            throw new SecurityException("Tenant context is required. Use your organization's URL.");
        }
        return tenantId;
    }

    // --- Branding Methods ---

    @Transactional(readOnly = true)
    public BrandingRequestDto getTenantBranding() {
        Long tenantId = getTenantIdFromContextOrFail();
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + tenantId));
        return mapTenantToBrandingDto(tenant);
    }

    @Transactional
    public BrandingRequestDto updateTenantBranding(BrandingRequestDto request) {
        Long tenantId = getTenantIdFromContextOrFail();
        String newSubdomain = request.getSubdomain().toLowerCase().trim();

        // Check for subdomain conflicts
        Optional<Tenant> existingTenant = tenantRepository.findBySubdomain(newSubdomain);
        if (existingTenant.isPresent() && !existingTenant.get().getId().equals(tenantId)) {
            log.warn("Branding update failed: Subdomain '{}' already used by tenant {}",
                    newSubdomain, existingTenant.get().getId());
            throw new ResourceAlreadyExistsException(
                    "This branding name (subdomain) is already in use. Please choose another.");
        }

        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + tenantId));

        tenant.setSubdomain(newSubdomain);
        tenant.setBrandingLogoUrl(StringUtils.hasText(request.getBrandingLogoUrl()) ?
                request.getBrandingLogoUrl() : null);
        tenant.setBrandingPrimaryColor(StringUtils.hasText(request.getBrandingPrimaryColor()) ?
                request.getBrandingPrimaryColor() : null);

        Tenant savedTenant = tenantRepository.save(tenant);
        log.info("✓ Tenant branding updated: tenantId={}, subdomain='{}'",
                savedTenant.getId(), savedTenant.getSubdomain());
        return mapTenantToBrandingDto(savedTenant);
    }

    private BrandingRequestDto mapTenantToBrandingDto(Tenant tenant) {
        return BrandingRequestDto.builder()
                .subdomain(tenant.getSubdomain())
                .brandingLogoUrl(tenant.getBrandingLogoUrl())
                .brandingPrimaryColor(tenant.getBrandingPrimaryColor())
                .build();
    }

    // --- User Management Methods ---

    @Transactional(readOnly = true)
    public List<UserInfo> findAllUsers() {
        Long tenantId = getTenantIdFromContextOrFail();
        log.info("→ Fetching all users for tenantId: {}", tenantId);

        // CRITICAL FIX: Use explicit tenant filtering instead of relying on aspect
        List<User> users = userRepository.findAll().stream()
                .filter(user -> user.getTenant() != null && user.getTenant().getId().equals(tenantId))
                .collect(Collectors.toList());

        log.info("✓ Found {} users for tenantId: {}", users.size(), tenantId);
        return users.stream()
                .map(this::mapToUserInfo)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public UserInfo findUserById(Long id) {
        Long tenantId = getTenantIdFromContextOrFail();
        log.info("→ Fetching user: id={}, tenantId={}", id, tenantId);

        // Use explicit tenant-aware query
        User user = userRepository.findById(id)
                .filter(u -> u.getTenant() != null && u.getTenant().getId().equals(tenantId))
                .orElseThrow(() -> {
                    log.error("✗ User not found or access denied: id={}, tenantId={}", id, tenantId);
                    return new EntityNotFoundException("User not found with id: " + id);
                });

        log.info("✓ User found: id={}, username='{}'", id, user.getUsername());
        return mapToUserInfo(user);
    }

    @Transactional
    public UserInfo createUser(SignUpRequest request) {
        Long tenantId = getTenantIdFromContextOrFail();
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + tenantId));

        log.info("→ Creating user: username='{}', tenantId={}", request.getUsername(), tenantId);

        // Check for duplicates within tenant
        if (userRepository.existsByUsernameAndTenantId(request.getUsername(), tenantId)) {
            log.warn("Create failed - username '{}' exists in tenant {}", request.getUsername(), tenantId);
            throw new ResourceAlreadyExistsException("Username already exists in your organization");
        }
        if (userRepository.existsByEmailAndTenantId(request.getEmail(), tenantId)) {
            log.warn("Create failed - email '{}' exists in tenant {}", request.getEmail(), tenantId);
            throw new ResourceAlreadyExistsException("Email already exists in your organization");
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .roles(StringUtils.hasText(request.getRoles()) ? request.getRoles() : "ROLE_USER")
                .enabled(true)
                .tenant(tenant)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .authProvider(User.AuthProvider.LOCAL)
                .build();

        User savedUser = userRepository.save(user);
        log.info("✓ User created: id={}, username='{}'", savedUser.getId(), savedUser.getUsername());
        return mapToUserInfo(savedUser);
    }

    @Transactional
    public UserInfo updateUser(Long id, UserUpdateRequest request) {
        Long tenantId = getTenantIdFromContextOrFail();
        log.info("→ Updating user: id={}, tenantId={}", id, tenantId);

        // Find user with tenant validation
        User user = userRepository.findById(id)
                .filter(u -> u.getTenant() != null && u.getTenant().getId().equals(tenantId))
                .orElseThrow(() -> {
                    log.error("✗ Update failed - User not found: id={}, tenantId={}", id, tenantId);
                    return new EntityNotFoundException("User not found with id: " + id);
                });

        // Check for username conflicts within tenant
        if (StringUtils.hasText(request.getUsername()) && !user.getUsername().equals(request.getUsername())) {
            if (userRepository.existsByUsernameAndTenantId(request.getUsername(), tenantId)) {
                throw new ResourceAlreadyExistsException("Username already exists in your organization");
            }
            user.setUsername(request.getUsername());
        }

        // Check for email conflicts within tenant
        if (StringUtils.hasText(request.getEmail()) && !user.getEmail().equals(request.getEmail())) {
            if (userRepository.existsByEmailAndTenantId(request.getEmail(), tenantId)) {
                throw new ResourceAlreadyExistsException("Email already exists in your organization");
            }
            user.setEmail(request.getEmail());
        }

        // Apply other updates
        if (StringUtils.hasText(request.getFirstName())) user.setFirstName(request.getFirstName());
        if (StringUtils.hasText(request.getLastName())) user.setLastName(request.getLastName());
        if (StringUtils.hasText(request.getRoles())) {
            log.debug("Updating roles for user {}: {}", id, request.getRoles());
            user.setRoles(request.getRoles());
        }
        if (StringUtils.hasText(request.getPassword())) {
            log.debug("Updating password for user {}", id);
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        }

        User updatedUser = userRepository.save(user);
        log.info("✓ User updated: id={}, username='{}'", updatedUser.getId(), updatedUser.getUsername());
        return mapToUserInfo(updatedUser);
    }

    @Transactional
    public void deleteUser(Long id) {
        Long tenantId = getTenantIdFromContextOrFail();
        log.info("→ Deleting user: id={}, tenantId={}", id, tenantId);

        // Find user with tenant validation
        User user = userRepository.findById(id)
                .filter(u -> u.getTenant() != null && u.getTenant().getId().equals(tenantId))
                .orElseThrow(() -> {
                    log.error("✗ Delete failed - User not found: id={}, tenantId={}", id, tenantId);
                    return new EntityNotFoundException("User not found with id: " + id);
                });

        userRepository.delete(user);
        log.info("✓ User deleted: id={}", id);
    }

    private UserInfo mapToUserInfo(User user) {
        return UserInfo.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .authProvider(user.getAuthProvider().name())
                .roles(user.getRoles())
                .build();
    }
}