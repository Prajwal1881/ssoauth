package com.example.ssoauth.config;

import com.example.ssoauth.repository.TenantRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityNotFoundException;
import jakarta.persistence.PersistenceContext;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.hibernate.Session;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class TenantFilterAspect {

    @PersistenceContext
    private EntityManager entityManager;

    @Autowired
    private TenantRepository tenantRepository;

    /**
     * FIX: The pointcut now excludes TenantRepository to prevent a StackOverflowError.
     * It intercepts all repository methods *except* those on the TenantRepository bean.
     */
    @Before("execution(* com.example.ssoauth.repository..*(..)) && !target(com.example.ssoauth.repository.TenantRepository)")
    public void applyTenantFilter() {

        Session session = entityManager.unwrap(Session.class);
        String subdomain = TenantContext.getCurrentTenant();

        if (subdomain != null) {
            // A tenant subdomain was detected.

            // This call to TenantRepository will NOT be intercepted by this aspect,
            // which prevents the infinite loop.
            Long tenantId = tenantRepository.findBySubdomain(subdomain)
                    .orElseThrow(() -> new EntityNotFoundException("Invalid tenant: " + subdomain))
                    .getId();

            if (isSuperAdmin()) {
                session.disableFilter("tenantFilter");
            } else {
                session.enableFilter("tenantFilter").setParameter("tenantId", tenantId);
            }
        } else {
            // No tenant subdomain (main domain).
            session.disableFilter("tenantFilter");
        }
    }

    private boolean isSuperAdmin() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            return authentication.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_SUPER_ADMIN"));
        }
        return false;
    }
}