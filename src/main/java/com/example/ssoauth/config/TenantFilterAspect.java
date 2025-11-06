package com.example.ssoauth.config;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.hibernate.Session;
import org.springframework.security.core.Authentication; // NEW IMPORT
import org.springframework.security.core.context.SecurityContextHolder; // NEW IMPORT
import org.springframework.stereotype.Component;

@Aspect
@Component
public class TenantFilterAspect {

    @PersistenceContext
    private EntityManager entityManager;

    @Before("within(com.example.ssoauth.repository..*) && !bean(tenantRepository)")
    public void applyTenantFilter() {

        Session session = entityManager.unwrap(Session.class);
        Long tenantId = TenantContext.getCurrentTenant();

        if (tenantId != null) {
            // --- 1. Tenant Found ---
            // A tenant ID was detected. ALWAYS filter by this tenant.
            session.enableFilter("tenantFilter").setParameter("tenantId", tenantId);

        } else {
            // --- 2. No Tenant Found (Root Domain or Invalid Domain) ---
            // Check if the user is a Super Admin.
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();

            if (auth != null && auth.isAuthenticated() &&
                    auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_SUPER_ADMIN"))) {

                // User is an authenticated Super Admin. Disable filtering.
                session.disableFilter("tenantFilter");
            } else {
                // User is anonymous, a regular user, or a non-Super-Admin on the root domain.
                // Enforce filtering with an impossible ID (e.g., 0) to prevent all data leaks.
                session.enableFilter("tenantFilter").setParameter("tenantId", 0L);
            }
        }
    }
}