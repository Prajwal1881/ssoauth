package com.example.ssoauth.config;

import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.entity.SsoProviderType;
import com.example.ssoauth.service.SsoConfigService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource; // NEW IMPORT
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.core.userdetails.UserDetailsService; // NEW IMPORT
import org.springframework.stereotype.Component;

import java.util.Base64; // NEW IMPORT
import java.util.Optional;
// REMOVED File, Path, and Files imports

/**
 * Dynamically creates Kerberos/SPNEGO authentication components
 * based on tenant-specific configuration from the database.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DynamicKerberosConfig {

    private final SsoConfigService ssoConfigService;
    // NEW: Inject UserDetailsService to link user accounts after Kerberos validation
    private final UserDetailsService userDetailsService;

    /**
     * Creates a SPNEGO authentication filter for the current tenant
     * if Kerberos is enabled.
     */
    public SpnegoAuthenticationProcessingFilter createSpnegoFilter(
            AuthenticationManager authManager,
            AuthenticationSuccessHandler successHandler) {

        SpnegoAuthenticationProcessingFilter filter = new SpnegoAuthenticationProcessingFilter();
        filter.setAuthenticationManager(authManager);
        filter.setSuccessHandler(successHandler);
        // We no longer check isKerberosEnabled() here, the AuthManager will do it
        return filter;
    }

    /**
     * Creates a Kerberos authentication provider for the CURRENT tenant.
     * This is now called PER-REQUEST by the tenant-aware AuthenticationManager.
     * Returns null if no enabled Kerberos config exists for the current tenant.
     */
    public KerberosServiceAuthenticationProvider createKerberosProvider() {
        try {
            Long tenantId = TenantContext.getCurrentTenant();
            if (tenantId == null) {
                log.debug("No tenant context - skipping Kerberos provider creation");
                return null;
            }

            // Find enabled Kerberos config for this tenant
            Optional<SsoProviderConfig> kerberosConfigOpt = ssoConfigService.getAllConfigEntities()
                    .stream()
                    .filter(c -> c.getProviderType() == SsoProviderType.KERBEROS && c.isEnabled())
                    .findFirst();

            if (kerberosConfigOpt.isEmpty()) {
                log.debug("No enabled Kerberos config for tenant {}", tenantId);
                return null;
            }

            SsoProviderConfig config = kerberosConfigOpt.get();
            if (config.getKerberosKeytabBase64() == null || config.getKerberosKeytabBase64().isEmpty()) {
                log.error("Kerberos config for tenant {} is missing keytab data.", tenantId);
                return null;
            }

            log.info("Creating Kerberos provider for tenant {} with SPN: {}",
                    tenantId, config.getKerberosServicePrincipal());

            // --- IMPROVEMENT: Load Keytab from Base64 directly into memory ---
            byte[] keytabBytes = Base64.getDecoder().decode(config.getKerberosKeytabBase64());
            Resource keytabResource = new ByteArrayResource(keytabBytes);

            // Create ticket validator
            SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
            ticketValidator.setServicePrincipal(config.getKerberosServicePrincipal());
            ticketValidator.setKeyTabLocation(keytabResource); // Use the in-memory resource
            ticketValidator.setDebug(true); // Enable for troubleshooting
            ticketValidator.afterPropertiesSet(); // Initialize the validator

            // Create authentication provider
            KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
            provider.setTicketValidator(ticketValidator);

            // CRITICAL: Link to UserDetailsService to load user roles/details
            provider.setUserDetailsService(userDetailsService);

            return provider;

        } catch (Exception e) {
            log.error("Failed to create Kerberos provider: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Creates SPNEGO entry point for 401 challenges
     */
    public SpnegoEntryPoint createSpnegoEntryPoint() {
        // Fallback to /login if SPNEGO fails
        return new SpnegoEntryPoint("/login");
    }

    /**
     * Extracts username from Kerberos principal based on config
     * (This is a helper for AuthService, can be removed if AuthService handles it)
     */
    public String extractUsername(String principal, SsoProviderConfig config) {
        if (principal == null) return null;

        String attributeType = config.getKerberosUserNameAttribute();
        if (attributeType == null) attributeType = "username";

        switch (attributeType.toLowerCase()) {
            case "email":
            case "upn":
                // Return full principal as email (user@REALM)
                return principal.toLowerCase();

            case "username":
            default:
                // Extract username before @ symbol
                return principal.split("@")[0];
        }
    }

    // --- REMOVED: createTempKeytab method is no longer needed ---

    /**
     * Checks if Kerberos is enabled for the current tenant
     * (Still useful for other checks, but not for filter creation)
     */
    public boolean isKerberosEnabled() {
        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) return false;

        return ssoConfigService.getAllConfigEntities().stream()
                .anyMatch(c -> c.getProviderType() == SsoProviderType.KERBEROS && c.isEnabled());
    }
}