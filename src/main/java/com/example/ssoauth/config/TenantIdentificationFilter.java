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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

/**
 * CRITICAL: This filter MUST run before Spring Security to ensure
 * the tenant context is available during authentication.
 */
@Component
@RequiredArgsConstructor
@Slf4j
@Order(1)
public class TenantIdentificationFilter implements Filter {

    private final TenantRepository tenantRepository;

    @Value("${app.base-domain}")
    private String baseDomain;

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