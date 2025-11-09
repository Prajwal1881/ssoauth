package com.example.ssoauth.security;

import com.example.ssoauth.config.TenantContext;
import com.example.ssoauth.entity.User;
import com.example.ssoauth.repository.TenantRepository;
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
    private final TenantRepository tenantRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {

        // --- THIS IS THE FIX ---
        // Normalize the incoming username/email to lowercase to match the database
        String lowercaseUsernameOrEmail = usernameOrEmail.toLowerCase();
        // --- END FIX ---

        Long tenantId = TenantContext.getCurrentTenant();
        Optional<User> userOpt;

        if (tenantId != null) {
            // This is a tenant-specific login (e.g., acme.localhost:8080)
            log.debug("Loading user {} for tenantId: {}", lowercaseUsernameOrEmail, tenantId);

            // 1. Find user by tenant ID
            userOpt = userRepository.findByTenantIdAndUsernameOrTenantIdAndEmail(tenantId, lowercaseUsernameOrEmail, tenantId, lowercaseUsernameOrEmail);

        } else {
            // This is a main domain login (Super Admin)
            log.debug("Loading user {} for root (tenant_id IS NULL)", lowercaseUsernameOrEmail);
            userOpt = userRepository.findByUsernameOrEmailAndTenantIsNull(lowercaseUsernameOrEmail, lowercaseUsernameOrEmail);

            if (userOpt.isPresent() && !userOpt.get().hasRole("ROLE_SUPER_ADMIN")) {
                log.warn("Tenant user {} attempted login from main domain. Denied.", lowercaseUsernameOrEmail);
                throw new UsernameNotFoundException("Please use your organization's login URL.");
            }
        }

        User user = userOpt.orElseThrow(() ->
                new UsernameNotFoundException("User not found with username or email: " + lowercaseUsernameOrEmail));

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