//package com.example.ssoauth.config;
//
//import com.example.ssoauth.repository.TenantRepository;
//import jakarta.persistence.EntityManager;
//import jakarta.persistence.EntityNotFoundException;
//import jakarta.persistence.PersistenceContext;
//import org.aspectj.lang.annotation.Aspect;
//import org.aspectj.lang.annotation.Before;
//import org.hibernate.Session;
//import org.springframework.beans.factory.annotation.Autowired;
//// REMOVED: import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.stereotype.Component;
//
//@Aspect
//@Component
//public class TenantFilterAspect {
//
//    @PersistenceContext
//    private EntityManager entityManager;
//
//    @Autowired
//    private TenantRepository tenantRepository;
//
//    /**
//     * FIX: Changed pointcut from 'execution()' to 'within()'
//     * This is more reliable for matching methods on Spring Data JPA proxies.
//     * This will now correctly intercept calls like 'userRepository.findAll()'.
//     */
//    @Before("within(com.example.ssoauth.repository..*) && !bean(tenantRepository)")
//    public void applyTenantFilter() {
//
//        Session session = entityManager.unwrap(Session.class);
//        String subdomain = TenantContext.getCurrentTenant();
//
//        if (subdomain != null) {
//            // A tenant subdomain was detected (e.g., "example.localhost").
//            // ALWAYS filter by this tenant.
//
//            // This call to TenantRepository will NOT be intercepted by this aspect,
//            // because of the !bean(tenantRepository) pointcut.
//            Long tenantId = tenantRepository.findBySubdomain(subdomain)
//                    .orElseThrow(() -> new EntityNotFoundException("Invalid tenant: " + subdomain))
//                    .getId();
//
//            session.enableFilter("tenantFilter").setParameter("tenantId", tenantId);
//
//        } else {
//            // No tenant subdomain (main domain).
//            // This is the Super-Admin context. Disable filtering.
//            session.disableFilter("tenantFilter");
//        }
//    }
//}