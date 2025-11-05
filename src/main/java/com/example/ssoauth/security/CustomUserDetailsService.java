package com.example.ssoauth.security;

import com.example.ssoauth.config.TenantContext;
import com.example.ssoauth.entity.User;
import com.example.ssoauth.repository.TenantRepository; // NEW IMPORT
import com.example.ssoauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final TenantRepository tenantRepository; // NEW IMPORT

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {

        // --- FIX: Get subdomain string from context ---
        String subdomain = TenantContext.getCurrentTenant();
        Optional<User> userOpt;

        if (subdomain != null) {
            // This is a tenant-specific login (e.g., acme.localhost:8080)
            log.debug("Loading user {} for subdomain: {}", usernameOrEmail, subdomain);

            // 1. Find tenant ID from subdomain
            Long tenantId = tenantRepository.findBySubdomain(subdomain)
                    .orElseThrow(() -> new UsernameNotFoundException("Invalid tenant: " + subdomain))
                    .getId();

            // 2. Find user by tenant ID
            userOpt = userRepository.findByTenantIdAndUsernameOrTenantIdAndEmail(tenantId, usernameOrEmail, tenantId, usernameOrEmail);

        } else {
            // This is a main domain login (Super Admin)
            log.debug("Loading user {} for root (tenant_id IS NULL)", usernameOrEmail);
            userOpt = userRepository.findByUsernameOrEmailAndTenantIsNull(usernameOrEmail, usernameOrEmail);

            if (userOpt.isPresent() && !userOpt.get().hasRole("ROLE_SUPER_ADMIN")) {
                log.warn("Tenant user {} attempted login from main domain. Denied.", usernameOrEmail);
                throw new UsernameNotFoundException("Please use your organization's login URL.");
            }
        }

        User user = userOpt.orElseThrow(() ->
                new UsernameNotFoundException("User not found with username or email: " + usernameOrEmail));

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.isEnabled(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isAccountNonLocked(),
                user.getAuthorities()
        );
    }

    @Transactional
    public UserDetails loadUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + id));

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.isEnabled(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isAccountNonLocked(),
                user.getAuthorities()
        );
    }
}