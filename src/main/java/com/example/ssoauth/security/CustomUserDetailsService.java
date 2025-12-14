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

        Long tenantId = TenantContext.getCurrentTenant();
        Optional<User> userOpt = Optional.empty();

        if (tenantId != null) {
            log.debug("Loading user '{}' for tenantId: {}", usernameOrEmail, tenantId);

            // --- FIX: Split the lookup for reliability ---

            // 1. Try finding by Username first (This matches the JWT 'sub')
            userOpt = userRepository.findByUsernameAndTenantId(usernameOrEmail, tenantId);

            // 2. If not found, try finding by Email
            if (userOpt.isEmpty()) {
                userOpt = userRepository.findByEmailAndTenantId(usernameOrEmail, tenantId);
            }

        } else {
            // Super Admin / Root Domain Login
            log.debug("Loading user '{}' for root (tenant_id IS NULL)", usernameOrEmail);
            userOpt = userRepository.findByUsernameOrEmailAndTenantIsNull(usernameOrEmail, usernameOrEmail);

            if (userOpt.isPresent() && !userOpt.get().hasRole("ROLE_SUPER_ADMIN")) {
                log.warn("Tenant user {} attempted login from main domain. Denied.", usernameOrEmail);
                throw new UsernameNotFoundException("Please use your organization's login URL.");
            }
        }

        User user = userOpt.orElseThrow(() -> {
            log.error("Login Failed: User '{}' not found in Tenant {}", usernameOrEmail, tenantId);
            return new UsernameNotFoundException("User not found: " + usernameOrEmail);
        });

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