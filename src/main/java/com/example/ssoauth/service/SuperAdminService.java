package com.example.ssoauth.service;

import com.example.ssoauth.dto.*;
import com.example.ssoauth.entity.SsoProviderConfig; // NEW IMPORT
import com.example.ssoauth.entity.SsoProviderType; // NEW IMPORT
import com.example.ssoauth.entity.Tenant;
import com.example.ssoauth.entity.User;
import com.example.ssoauth.exception.ResourceAlreadyExistsException;
import com.example.ssoauth.repository.SsoProviderConfigRepository; // NEW IMPORT
import com.example.ssoauth.repository.TenantRepository;
import com.example.ssoauth.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set; // NEW IMPORT
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class SuperAdminService {

    private final TenantRepository tenantRepository;
    private final UserRepository userRepository;
    private final SsoProviderConfigRepository ssoConfigRepository; // NEW REPO
    private final PasswordEncoder passwordEncoder;

    // --- Tenant Management ---

    @Transactional
    public TenantDto createTenant(TenantDto tenantDto) {
        log.info("Super Admin creating tenant with subdomain: {}", tenantDto.getSubdomain());
        if (tenantRepository.findBySubdomain(tenantDto.getSubdomain()).isPresent()) {
            throw new ResourceAlreadyExistsException("Subdomain already exists: " + tenantDto.getSubdomain());
        }

        Tenant tenant = new Tenant();
        BeanUtils.copyProperties(tenantDto, tenant, "id");

        Tenant savedTenant = tenantRepository.save(tenant);
        log.info("Tenant created with ID: {}", savedTenant.getId());
        return mapToTenantDto(savedTenant);
    }


    @Transactional
    public void deleteTenant(Long id) {
        log.info("Super Admin initiating deletion of tenant ID: {}", id);

        Tenant tenant = tenantRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + id));

        String tenantName = tenant.getName();
        String subdomain = tenant.getSubdomain();

        // Log deletion details for audit trail
        log.info("Deleting tenant: {} (subdomain: {})", tenantName, subdomain);

        // Step 1: Count and log associated data for audit
        Long userCount = userRepository.countByTenant(tenant);
        List<SsoProviderConfig> ssoConfigs = ssoConfigRepository.findByTenantId(tenant.getId());

        log.info("Tenant {} has {} users and {} SSO configurations to be deleted",
                tenantName, userCount, ssoConfigs.size());

        // Step 2: Delete associated SSO configurations first
        if (!ssoConfigs.isEmpty()) {
            ssoConfigRepository.deleteAll(ssoConfigs);
            log.info("Deleted {} SSO configurations for tenant {}", ssoConfigs.size(), tenantName);
        }

        // Step 3: Delete associated users
        // We need to fetch users explicitly since we need the tenant filter disabled
        List<User> tenantUsers = userRepository.findAll().stream()
                .filter(u -> u.getTenant() != null && u.getTenant().getId().equals(id))
                .collect(Collectors.toList());

        if (!tenantUsers.isEmpty()) {
            userRepository.deleteAll(tenantUsers);
            log.info("Deleted {} users for tenant {}", tenantUsers.size(), tenantName);
        }

        // Step 4: Finally delete the tenant itself
        tenantRepository.delete(tenant);
        log.info("Successfully deleted tenant: {} (ID: {})", tenantName, id);
    }


    /**
     * UPDATED: This method now returns the enhanced DTO with stats.
     */
    public List<TenantDetailDto> getAllTenantsWithDetails() {
        log.info("Super Admin fetching all tenants with details");
        List<Tenant> tenants = tenantRepository.findAll();

        // This is an N+1 query problem (1 for tenants + N for counts + N for providers).
        // For a high-scale app, this should be optimized with a single native query.
        // For this system, this is clear and acceptable.

        return tenants.stream()
                .map(this::mapToTenantDetailDto)
                .collect(Collectors.toList());
    }

    public TenantDto getTenantById(Long id) {
        log.info("Super Admin fetching tenant by ID: {}", id);
        Tenant tenant = tenantRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + id));
        return mapToTenantDto(tenant);
    }

    @Transactional
    public TenantDto updateTenant(Long id, TenantDto tenantDto) {
        log.info("Super Admin updating tenant ID: {}", id);
        Tenant tenant = tenantRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + id));

        if (!tenant.getSubdomain().equals(tenantDto.getSubdomain())) {
            if (tenantRepository.findBySubdomain(tenantDto.getSubdomain()).isPresent()) {
                throw new ResourceAlreadyExistsException("Subdomain already exists: " + tenantDto.getSubdomain());
            }
        }

        BeanUtils.copyProperties(tenantDto, tenant, "id", "createdAt", "updatedAt");
        Tenant updatedTenant = tenantRepository.save(tenant);
        return mapToTenantDto(updatedTenant);
    }

    // NEW METHOD: Public Onboarding Flow
    @Transactional
    public TenantDto registerNewTenant(TenantRegistrationRequest request) {
        log.info("Public Registration: Creating tenant '{}' with subdomain '{}'", request.getTenantName(), request.getSubdomain());

        // 1. Validate Subdomain Uniqueness
        if (tenantRepository.findBySubdomain(request.getSubdomain()).isPresent()) {
            throw new ResourceAlreadyExistsException("Subdomain '" + request.getSubdomain() + "' is already taken.");
        }

        // 2. Validate Admin Username/Email Global Uniqueness (Optional, but good for main domain)
        // Since the new user will belong to the new tenant, we strictly only need to check inside that tenant context,
        // but checking globally prevents confusion if you use email for discovery later.
        if (userRepository.existsByEmailAndTenantIdIsNull(request.getEmail())) {
            throw new ResourceAlreadyExistsException("Email is already registered in the system.");
        }

        // 3. Create Tenant
        Tenant tenant = Tenant.builder()
                .name(request.getTenantName())
                .subdomain(request.getSubdomain().toLowerCase())
                .build();
        Tenant savedTenant = tenantRepository.save(tenant);

        // 4. Create Admin User linked to Tenant
        User adminUser = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .tenant(savedTenant) // Link to new tenant
                .roles("ROLE_ADMIN,ROLE_USER") // Assign Admin Role
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .authProvider(User.AuthProvider.LOCAL)
                .build();

        userRepository.save(adminUser);

        log.info("Successfully registered tenant {} and admin user {}", savedTenant.getId(), adminUser.getUsername());

        return mapToTenantDto(savedTenant);
    }
    // --- User Management (Onboarding) ---

    @Transactional
    public UserInfo onboardTenantAdmin(Long tenantId, SignUpRequest request) {
        log.info("Super Admin onboarding admin for tenant ID: {}", tenantId);
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + tenantId));

        if (userRepository.existsByUsernameAndTenantId(request.getUsername(), tenantId)) {
            throw new ResourceAlreadyExistsException("Username already exists in this tenant");
        }
        if (userRepository.existsByEmailAndTenantId(request.getEmail(), tenantId)) {
            throw new ResourceAlreadyExistsException("Email already exists in this tenant");
        }

        User adminUser = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .tenant(tenant)
                .roles("ROLE_ADMIN,ROLE_USER") // Customer Admins are also Users
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .authProvider(User.AuthProvider.LOCAL)
                .build();

        User savedUser = userRepository.save(adminUser);
        log.info("Customer Admin created with ID: {} for tenant: {}", savedUser.getId(), tenantId);
        return mapToUserInfo(savedUser);
    }

    // --- Mappers ---

    private TenantDto mapToTenantDto(Tenant tenant) {
        return TenantDto.builder()
                .id(tenant.getId())
                .name(tenant.getName())
                .subdomain(tenant.getSubdomain())
                .brandingLogoUrl(tenant.getBrandingLogoUrl())
                .brandingPrimaryColor(tenant.getBrandingPrimaryColor())
                .build();
    }

    // NEW: Mapper for the enhanced DTO
    private TenantDetailDto mapToTenantDetailDto(Tenant tenant) {
        // 1. Get User Count
        Long userCount = userRepository.countByTenant(tenant);

        // 2. Get Enabled Providers
        List<SsoProviderConfig> enabledConfigs = ssoConfigRepository.findByTenantIdAndEnabledTrue(tenant.getId());
        Set<String> providerTypes = enabledConfigs.stream()
                .map(SsoProviderConfig::getProviderType)
                .map(SsoProviderType::name)
                .collect(Collectors.toSet()); // Use Set to avoid duplicates (e.g., 2 OIDC)

        return TenantDetailDto.builder()
                .id(tenant.getId())
                .name(tenant.getName())
                .subdomain(tenant.getSubdomain())
                .brandingLogoUrl(tenant.getBrandingLogoUrl())
                .brandingPrimaryColor(tenant.getBrandingPrimaryColor())
                .userCount(userCount)
                .enabledProviders(providerTypes.stream().toList()) // Convert Set back to List
                .build();
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