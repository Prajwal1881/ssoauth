package com.example.ssoauth.service;

import com.example.ssoauth.dto.SignUpRequest;
import com.example.ssoauth.dto.TenantDetailDto; // UPDATED DTO
import com.example.ssoauth.dto.TenantDto;
import com.example.ssoauth.dto.UserInfo;
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