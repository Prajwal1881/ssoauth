package com.example.ssoauth.config;

import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.entity.SsoProviderType;
import com.example.ssoauth.service.SsoConfigService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Optional;

/**
 * Dynamically creates Kerberos/SPNEGO authentication components
 * based on tenant-specific configuration from the database.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DynamicKerberosConfig {

    private final SsoConfigService ssoConfigService;

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

        return filter;
    }

    /**
     * Creates a Kerberos authentication provider for the current tenant.
     * Returns null if no enabled Kerberos config exists.
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
            log.info("Creating Kerberos provider for tenant {} with SPN: {}",
                    tenantId, config.getKerberosServicePrincipal());

            // Create temporary keytab file from Base64 data
            File keytabFile = createTempKeytab(config.getKerberosKeytabBase64());

            // Create ticket validator
            SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
            ticketValidator.setServicePrincipal(config.getKerberosServicePrincipal());
            ticketValidator.setKeyTabLocation(new ByteArrayResource(Files.readAllBytes(keytabFile.toPath())));
            ticketValidator.setDebug(true); // Enable for troubleshooting
            ticketValidator.afterPropertiesSet();

            // Create authentication provider
            KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
            provider.setTicketValidator(ticketValidator);
            provider.setUserDetailsService(username -> {
                // This is called after Kerberos validation succeeds
                // You can load additional user details here
                log.info("Kerberos authentication succeeded for: {}", username);
                return null; // Will be handled by success handler
            });

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
        return new SpnegoEntryPoint("/login");
    }

    /**
     * Extracts username from Kerberos principal based on config
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

    /**
     * Creates a temporary keytab file from Base64 data
     */
    private File createTempKeytab(String base64Keytab) throws Exception {
        byte[] keytabBytes = Base64.getDecoder().decode(base64Keytab);

        // Create temp file
        Path tempPath = Files.createTempFile("kerberos-", ".keytab");
        Files.write(tempPath, keytabBytes);

        File keytabFile = tempPath.toFile();
        keytabFile.deleteOnExit(); // Clean up on app shutdown

        // Set restrictive permissions (Unix-like systems only)
        keytabFile.setReadable(false, false);
        keytabFile.setReadable(true, true);
        keytabFile.setWritable(false, false);

        log.info("Created temporary keytab file: {}", tempPath);
        return keytabFile;
    }

    /**
     * Checks if Kerberos is enabled for the current tenant
     */
    public boolean isKerberosEnabled() {
        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) return false;

        return ssoConfigService.getAllConfigEntities().stream()
                .anyMatch(c -> c.getProviderType() == SsoProviderType.KERBEROS && c.isEnabled());
    }
}