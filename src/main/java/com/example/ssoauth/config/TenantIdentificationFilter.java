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

@Component
@RequiredArgsConstructor
@Slf4j
@Order(1)
public class TenantIdentificationFilter implements Filter {

    private final TenantRepository tenantRepository;

    @Value("${app.base-domain}")
    private String baseDomain;

    private static final String SESSION_TENANT_ID_ATTR = "current_tenant_id";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String host = httpRequest.getServerName();
        String requestUri = httpRequest.getRequestURI();

        log.debug("TenantFilter processing - Host: '{}', URI: '{}'", host, requestUri);

        TenantContext.clear();

        try {
            if (host.endsWith("." + baseDomain)) {
                String subdomain = host.substring(0, host.indexOf("." + baseDomain));
                log.debug("Subdomain detected: '{}' from host: '{}'", subdomain, host);

                Optional<Tenant> tenantOpt = tenantRepository.findBySubdomain(subdomain);

                if (tenantOpt.isPresent()) {
                    Long tenantId = tenantOpt.get().getId();
                    log.debug("Tenant found: id={}, subdomain='{}'", tenantId, subdomain);

                    HttpSession session = httpRequest.getSession(false);
                    if (session != null) {
                        Long sessionTenantId = (Long) session.getAttribute(SESSION_TENANT_ID_ATTR);
                        log.debug("Existing session - sessionId: {}, sessionTenant: {}, currentTenant: {}",
                                session.getId(), sessionTenantId, tenantId);

                        boolean isOAuth2Callback = requestUri.startsWith("/login/oauth2/code/") ||
                                requestUri.startsWith("/login/saml2/sso/");

                        if (sessionTenantId != null && !sessionTenantId.equals(tenantId)) {
                            if (isOAuth2Callback) {
                                log.error("CRITICAL: Tenant mismatch during OAuth2 callback! Session tenant: {}, Current tenant: {}. " +
                                        "This indicates a security issue or misconfiguration.", sessionTenantId, tenantId);
                                httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN,
                                        "Tenant mismatch during authentication");
                                return;
                            } else {
                                log.warn("Tenant switch detected! Session had tenant {}, now accessing tenant {}. Invalidating session.",
                                        sessionTenantId, tenantId);
                                SecurityContextHolder.clearContext();
                                session.invalidate();
                                session = httpRequest.getSession(true);
                                log.info("New session created for tenant switch: sessionId={}, newTenant={}",
                                        session.getId(), tenantId);
                            }
                        }
                    } else {
                        session = httpRequest.getSession(true);
                        log.debug("Created new session: sessionId={} for tenant: {}", session.getId(), tenantId);
                    }

                    session.setAttribute(SESSION_TENANT_ID_ATTR, tenantId);
                    TenantContext.setCurrentTenant(tenantId);
                    log.debug("✓ Tenant context set: subdomain='{}', tenantId={}, sessionId={}",
                            subdomain, tenantId, session.getId());

                } else {
                    log.error("INVALID SUBDOMAIN: '{}' does not exist in database. Host: '{}'", subdomain, host);
                    httpResponse.sendError(HttpServletResponse.SC_NOT_FOUND,
                            "Organization not found: " + subdomain);
                    return;
                }

            } else {
                log.debug("Root domain access detected: host='{}', uri='{}'", host, requestUri);

                HttpSession session = httpRequest.getSession(false);
                if (session != null) {
                    Long sessionTenantId = (Long) session.getAttribute(SESSION_TENANT_ID_ATTR);
                    if (sessionTenantId != null) {
                        log.info("User moved from tenant {} to root domain. Clearing tenant session attribute.",
                                sessionTenantId);
                        session.removeAttribute(SESSION_TENANT_ID_ATTR);
                    }
                }
                log.debug("Root domain access - No tenant context set");
            }

            log.trace("Proceeding with filter chain for URI: {}", requestUri);
            chain.doFilter(request, response);
            log.trace("Filter chain completed for URI: {}", requestUri);

        } catch (Exception e) {
            log.error("CRITICAL: Tenant identification failed for host: '{}', URI: '{}'", host, requestUri, e);
            httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Tenant identification failed");
        } finally {
            log.trace("Clearing tenant context after request processing");
            TenantContext.clear();
        }
    }
}