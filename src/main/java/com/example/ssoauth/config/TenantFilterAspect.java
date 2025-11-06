package com.example.ssoauth.config;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.hibernate.Session;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * CRITICAL FIX: This aspect must run AFTER the transaction has started
 * to ensure the Hibernate filter is applied to the correct session.
 */
@Aspect
@Component
@Slf4j
@Order(100) // Run after transaction starts
public class TenantFilterAspect {

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * Apply tenant filter to all repository methods except TenantRepository itself.
     *
     * CRITICAL CHANGES:
     * 1. Added explicit session flush to ensure filter is applied
     * 2. Added defensive null checks
     * 3. Improved logging for debugging
     */
    @Before("within(com.example.ssoauth.repository..*) && !bean(tenantRepository)")
    public void applyTenantFilter() {
        try {
            Session session = entityManager.unwrap(Session.class);
            Long tenantId = TenantContext.getCurrentTenant();

            // CRITICAL: Always clear existing filters first to prevent stale state
            try {
                session.disableFilter("tenantFilter");
            } catch (Exception e) {
                // Filter might not exist yet, ignore
            }

            if (tenantId != null) {
                // --- TENANT-SCOPED ACCESS ---
                log.debug("Applying tenant filter for tenantId: {}", tenantId);
                session.enableFilter("tenantFilter").setParameter("tenantId", tenantId);

            } else {
                // --- ROOT DOMAIN ACCESS ---
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();

                if (auth != null && auth.isAuthenticated() &&
                        auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_SUPER_ADMIN"))) {
                    // Super Admin: Allow access to all data
                    log.debug("Super Admin access detected - tenant filter disabled");
                    // Filter remains disabled

                } else {
                    // Non-Super-Admin on root domain: Block all access
                    log.warn("Non-Super-Admin attempted root domain access - blocking with impossible tenant ID");
                    session.enableFilter("tenantFilter").setParameter("tenantId", -999L);
                }
            }

            // CRITICAL FIX: Flush the session to ensure filter is applied immediately
            session.flush();

        } catch (Exception e) {
            log.error("CRITICAL: Failed to apply tenant filter - this will cause data leaks!", e);
            throw new RuntimeException("Tenant isolation failed", e);
        }
    }
}