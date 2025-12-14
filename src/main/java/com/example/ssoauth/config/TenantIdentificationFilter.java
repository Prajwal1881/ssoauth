package com.example.ssoauth.config;

import com.example.ssoauth.entity.Tenant;
import com.example.ssoauth.repository.TenantRepository;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

/**
 * CRITICAL: This filter MUST run before Spring Security to ensure
 * the tenant context is available during authentication AND to handle
 * session isolation between tenants.
 */
@Component
@RequiredArgsConstructor
@Slf4j
@Order(1)
public class TenantIdentificationFilter implements Filter {

    private final TenantRepository tenantRepository;

    @Value("${app.base-domain}")
    private String baseDomain;

    // Session attribute to track current tenant
    private static final String SESSION_TENANT_ID_ATTR = "current_tenant_id";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String host = httpRequest.getServerName();
        String requestUri = httpRequest.getRequestURI();

        // Always clear context at the start
        TenantContext.clear();

        try {
            if (host.endsWith("." + baseDomain)) {
                // --- SUBDOMAIN DETECTED ---
                String subdomain = host.substring(0, host.indexOf("." + baseDomain));
                log.debug("Subdomain detected: '{}' from host: '{}'", subdomain, host);

                // Lookup tenant by subdomain
                Optional<Tenant> tenantOpt = tenantRepository.findBySubdomain(subdomain);

                if (tenantOpt.isPresent()) {
                    Long tenantId = tenantOpt.get().getId();

                    // ✅ NEW: Check if tenant has changed in the session
                    HttpSession session = httpRequest.getSession(false);
                    if (session != null) {
                        Long sessionTenantId = (Long) session.getAttribute(SESSION_TENANT_ID_ATTR);

                        if (sessionTenantId != null && !sessionTenantId.equals(tenantId)) {
                            // ✅ CRITICAL FIX: Tenant has changed! Clear OAuth2 state
                            log.warn("⚠️ Tenant switch detected! Session had tenant {}, now accessing tenant {}. Invalidating session.",
                                    sessionTenantId, tenantId);

                            // Clear security context
                            SecurityContextHolder.clearContext();

                            // Invalidate the old session to clear OAuth2 authorization requests
                            session.invalidate();

                            // Create new session
                            session = httpRequest.getSession(true);
                            log.info("✓ New session created for tenant switch: {}", tenantId);
                        }
                    } else {
                        // No session yet, create one
                        session = httpRequest.getSession(true);
                    }

                    // Store current tenant in session
                    session.setAttribute(SESSION_TENANT_ID_ATTR, tenantId);

                    TenantContext.setCurrentTenant(tenantId);
                    log.info("✓ Tenant context set: subdomain='{}', tenantId={}, uri='{}'",
                            subdomain, tenantId, requestUri);
                } else {
                    // CRITICAL: Invalid subdomain - return 404
                    log.error("✗ INVALID SUBDOMAIN: '{}' does not exist in database", subdomain);
                    httpResponse.sendError(HttpServletResponse.SC_NOT_FOUND,
                            "Organization not found: " + subdomain);
                    return; // Stop processing
                }

            } else {
                // --- ROOT DOMAIN ACCESS ---
                log.debug("Root domain access detected: host='{}', uri='{}'", host, requestUri);

                // For root domain, also track in session
                HttpSession session = httpRequest.getSession(false);
                if (session != null) {
                    Long sessionTenantId = (Long) session.getAttribute(SESSION_TENANT_ID_ATTR);
                    if (sessionTenantId != null) {
                        // User was on a tenant, now on root - clear their tenant session
                        log.info("⚠️ User moved from tenant {} to root domain. Clearing tenant session.",
                                sessionTenantId);
                        session.removeAttribute(SESSION_TENANT_ID_ATTR);
                    }
                }

                // TenantContext remains null (for Super Admin access)
            }

            // Proceed with the request
            chain.doFilter(request, response);

        } catch (Exception e) {
            log.error("CRITICAL: Tenant identification failed for host: {}", host, e);
            httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Tenant identification failed");
        } finally {
            // Always clean up
            TenantContext.clear();
        }
    }
}