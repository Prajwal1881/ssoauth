package com.example.ssoauth.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.server.CookieSameSiteSupplier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

/**
 * Session configuration to ensure proper session isolation between tenants.
 * This prevents OAuth2 state conflicts when switching between tenant subdomains.
 */
@Configuration
public class SessionConfig {

    /**
     * CRITICAL: Configures session cookies to be subdomain-specific.
     * This prevents session sharing between tenant1.localhost and tenant2.localhost.
     */
    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();

        // ✅ CRITICAL FIX: Set cookie domain to null to bind to exact subdomain
        // This ensures testing1.localhost and testing.localhost have separate sessions
        serializer.setDomainName(null);

        // Session cookie name
        serializer.setCookieName("TENANT_SESSION");

        // Cookie path
        serializer.setCookiePath("/");

        // Security settings
        serializer.setUseHttpOnlyCookie(true);
        serializer.setUseSecureCookie(false); // Set to true in production with HTTPS
        serializer.setSameSite("Lax"); // Allows OAuth2 redirects

        // Cookie max age (optional - session cookies by default)
        // serializer.setCookieMaxAge(3600); // 1 hour

        return serializer;
    }

    /**
     * Alternative approach using application.properties configuration.
     * You can use this instead of the bean above by adding to application.properties:
     *
     * server.servlet.session.cookie.name=TENANT_SESSION
     * server.servlet.session.cookie.domain=
     * server.servlet.session.cookie.http-only=true
     * server.servlet.session.cookie.secure=false
     * server.servlet.session.cookie.same-site=lax
     * server.servlet.session.cookie.path=/
     */
}