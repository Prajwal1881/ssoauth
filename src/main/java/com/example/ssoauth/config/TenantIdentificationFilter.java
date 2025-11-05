package com.example.ssoauth.config;

// REMOVED: import com.example.ssoauth.entity.Tenant;
// REMOVED: import com.example.ssoauth.repository.TenantRepository;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
// REMOVED: import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
@Order(1) // Runs BEFORE Spring Security
public class TenantIdentificationFilter implements Filter {

    // --- FIX: Removed TenantRepository ---

    @Value("${app.base-domain}")
    private String baseDomain;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String host = httpRequest.getServerName();

        TenantContext.clear();

        if (host.endsWith("." + baseDomain)) {
            String subdomain = host.substring(0, host.indexOf("." + baseDomain));

            // --- FIX: ONLY set the string, do not query the database ---
            TenantContext.setCurrentTenant(subdomain);
            log.debug("TenantContext set to subdomain: {}", subdomain);

        } else {
            log.debug("No subdomain detected (host: {}), operating in root/super-admin context.", host);
        }

        try {
            chain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }
}