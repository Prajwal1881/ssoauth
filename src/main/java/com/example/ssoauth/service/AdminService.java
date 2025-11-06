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
import jakarta.persistence.EntityManager; // REMOVED
import jakarta.persistence.EntityNotFoundException;
import jakarta.persistence.PersistenceContext; // REMOVED
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.Session; // REMOVED
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

    // REMOVED: EntityManager is no longer needed, Aspect handles filtering
    // @PersistenceContext
    // private EntityManager entityManager;

    /**
     * Helper to get the current tenant ID (Long) from the context.
     */
    private Long getTenantIdFromContext() {
        // --- FIX: Read Long ID directly from context ---
        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) {
            // This case should only apply to Super Admins on the root domain
            throw new EntityNotFoundException("No tenant context found. Access denied.");
        }
        return tenantId;
    }

    // --- Branding Methods ---

    @Transactional(readOnly = true)
    public BrandingRequestDto getTenantBranding() {
        Long tenantId = getTenantIdFromContext();
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found with ID: " + tenantId));

        return mapTenantToBrandingDto(tenant);
    }

    @Transactional
    public BrandingRequestDto updateTenantBranding(BrandingRequestDto request) {
        Long tenantId = getTenantIdFromContext();

        String newSubdomain = request.getSubdomain().toLowerCase().trim();

        Optional<Tenant> existingTenant = tenantRepository.findBySubdomain(newSubdomain);
        if (existingTenant.isPresent() && !existingTenant.get().getId().equals(tenantId)) {
            log.warn("Branding update failed: Subdomain '{}' already in use by tenant ID {}", newSubdomain, existingTenant.get().getId());
            throw new ResourceAlreadyExistsException("This branding name (subdomain) is already in use. Please choose another.");
        }

        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found with ID: " + tenantId));

        tenant.setSubdomain(newSubdomain);
        tenant.setBrandingLogoUrl(StringUtils.hasText(request.getBrandingLogoUrl()) ? request.getBrandingLogoUrl() : null);
        tenant.setBrandingPrimaryColor(StringUtils.hasText(request.getBrandingPrimaryColor()) ? request.getBrandingPrimaryColor() : null);

        Tenant savedTenant = tenantRepository.save(tenant);
        log.info("Tenant ID {} updated branding. New subdomain: {}", savedTenant.getId(), savedTenant.getSubdomain());

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

    /**
     * FIX: Removed manual session filtering. The TenantFilterAspect now handles this.
     */
    @Transactional(readOnly = true)
    public List<UserInfo> findAllUsers() {
        Long tenantId = getTenantIdFromContext();
        log.info("Fetching all users for admin (tenant context: {})", tenantId);

        // --- FIX: MANUAL FILTER CONTROL REMOVED ---
        // Session session = entityManager.unwrap(Session.class);
        // session.enableFilter("tenantFilter").setParameter("tenantId", tenantId);

        List<UserInfo> users = userRepository.findAll().stream() // AspectJ will filter this
                .map(this::mapToUserInfo)
                .collect(Collectors.toList());

        // session.disableFilter("tenantFilter"); // Always disable after use
        return users;
    }

    /**
     * FIX: Removed manual filter logic.
     */
    @Transactional(readOnly = true)
    public UserInfo findUserById(Long id) {
        Long tenantId = getTenantIdFromContext();
        log.info("Fetching user by ID: {} (tenant context: {})", id, tenantId);

        // --- FIX: MANUAL FILTER CONTROL REMOVED ---

        User user = userRepository.findById(id) // AspectJ will filter this
                .orElseThrow(() -> new EntityNotFoundException("User not found with id: " + id));

        // session.disableFilter("tenantFilter");
        return mapToUserInfo(user);
    }

    @Transactional
    public UserInfo createUser(SignUpRequest request) {
        Long tenantId = getTenantIdFromContext();
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + tenantId));

        log.info("Attempting to create user with username: {} for tenant: {}", request.getUsername(), tenantId);

        // These explicit checks are still good practice
        if (userRepository.existsByUsernameAndTenantId(request.getUsername(), tenantId)) {
            log.warn("Username already exists in tenant {}: {}", tenantId, request.getUsername());
            throw new ResourceAlreadyExistsException("Username already exists");
        }
        if (userRepository.existsByEmailAndTenantId(request.getEmail(), tenantId)) {
            log.warn("Email already exists in tenant {}: {}", tenantId, request.getEmail());
            throw new ResourceAlreadyExistsException("Email already exists");
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
        log.info("User created successfully with ID: {}", savedUser.getId());
        return mapToUserInfo(savedUser);
    }

    @Transactional
    public UserInfo updateUser(Long id, UserUpdateRequest request) {
        Long tenantId = getTenantIdFromContext();
        log.info("Attempting to update user with ID: {} in tenant: {}", id, tenantId);

        // --- FIX: MANUAL FILTER CONTROL REMOVED ---

        User user = userRepository.findById(id) // AspectJ will filter this
                .orElseThrow(() -> new EntityNotFoundException("User not found with id: " + id));

        // session.disableFilter("tenantFilter");

        // Explicit tenant-scoped checks are still good
        if (StringUtils.hasText(request.getUsername()) && !user.getUsername().equals(request.getUsername())) {
            if (userRepository.existsByUsernameAndTenantId(request.getUsername(), tenantId)) {
                throw new ResourceAlreadyExistsException("Username already exists");
            }
            user.setUsername(request.getUsername());
        }
        if (StringUtils.hasText(request.getEmail()) && !user.getEmail().equals(request.getEmail())) {
            if (userRepository.existsByEmailAndTenantId(request.getEmail(), tenantId)) {
                throw new ResourceAlreadyExistsException("Email already exists");
            }
            user.setEmail(request.getEmail());
        }

        if (StringUtils.hasText(request.getFirstName())) {
            user.setFirstName(request.getFirstName());
        }
        if (StringUtils.hasText(request.getLastName())) {
            user.setLastName(request.getLastName());
        }
        if (StringUtils.hasText(request.getRoles())) {
            log.debug("Updating roles for user ID {}: {}", id, request.getRoles());
            user.setRoles(request.getRoles());
        }
        if (StringUtils.hasText(request.getPassword())) {
            log.debug("Password change detected for user ID {}.", id);
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        }

        User updatedUser = userRepository.save(user);
        log.info("User updated successfully for ID: {}", updatedUser.getId());
        return mapToUserInfo(updatedUser);
    }

    @Transactional
    public void deleteUser(Long id) {
        Long tenantId = getTenantIdFromContext();
        log.info("Attempting to delete user with ID: {} in tenant: {}", id, tenantId);

        // --- FIX: MANUAL FILTER CONTROL REMOVED ---

        // The Aspect will filter existsById, so this check is now tenant-safe
        if (!userRepository.existsById(id)) {
            // session.disableFilter("tenantFilter"); // No need to disable what wasn't manually enabled
            log.warn("Delete failed: User not found with ID: {}", id);
            throw new EntityNotFoundException("User not found with id: " + id);
        }

        userRepository.deleteById(id); // AspectJ will filter this
        // session.disableFilter("tenantFilter");
        log.info("User deleted successfully with ID: {}", id);
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