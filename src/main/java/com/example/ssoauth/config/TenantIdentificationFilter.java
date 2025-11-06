package com.example.ssoauth.config;

import com.example.ssoauth.entity.Tenant; // NEW IMPORT
import com.example.ssoauth.repository.TenantRepository; // NEW IMPORT
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
import java.util.Optional; // NEW IMPORT

@Component
@RequiredArgsConstructor
@Slf4j
@Order(1) // Runs BEFORE Spring Security
public class TenantIdentificationFilter implements Filter {

    // --- FIX: Inject TenantRepository ---
    private final TenantRepository tenantRepository;

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

            // --- FIX: Perform DB lookup ONCE and store the Long ID ---
            Optional<Tenant> tenantOpt = tenantRepository.findBySubdomain(subdomain);

            if (tenantOpt.isPresent()) {
                Long tenantId = tenantOpt.get().getId();
                TenantContext.setCurrentTenant(tenantId);
                log.debug("TenantContext set to tenantId: {}", tenantId);
            } else {
                log.warn("Invalid subdomain detected and ignored: {}", subdomain);
                // TenantContext remains null
            }

        } else {
            log.debug("No subdomain detected (host: {}), operating in root/super-admin context.", host);
            // TenantContext remains null
        }

        try {
            chain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }
}