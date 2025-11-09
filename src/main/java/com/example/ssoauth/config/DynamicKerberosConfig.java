package com.example.ssoauth.config;

import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.entity.SsoProviderType;
import com.example.ssoauth.service.SsoConfigService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.FileSystemResource;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Optional;
import java.util.List;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

/**
 * Dynamically creates Kerberos/SPNEGO authentication components
 * based on tenant-specific configuration from the database.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DynamicKerberosConfig {

    private final SsoConfigService ssoConfigService;
    // REMOVED AuthService and UserDetailsService injections to break cycle

    /**
     * Creates a SPNEGO authentication filter.
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
     * Creates a Kerberos authentication provider for the CURRENT tenant.
     */
    public KerberosServiceAuthenticationProvider createKerberosProvider() {
        try {
            Long tenantId = TenantContext.getCurrentTenant();
            if (tenantId == null) {
                log.debug("No tenant context - skipping Kerberos provider creation");
                return null;
            }

            Optional<SsoProviderConfig> kerberosConfigOpt = ssoConfigService.getAllConfigEntities().stream()
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

            File keytabFile = createTempKeytab(config.getKerberosKeytabBase64(), tenantId);

            // Create ticket validator
            SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
            ticketValidator.setServicePrincipal(config.getKerberosServicePrincipal());
            ticketValidator.setKeyTabLocation(new FileSystemResource(keytabFile));
            ticketValidator.setDebug(true);
            ticketValidator.afterPropertiesSet();

            // Create authentication provider
            KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
            provider.setTicketValidator(ticketValidator);

            // --- THIS IS THE FIX ---
            // Use a *dummy* UserDetailsService.
            // Its *only* job is to wrap the principal name (user@REALM)
            // so Spring Security is happy. The *real* user logic
            // (JIT provisioning and role loading) will happen in the SuccessHandler.
            provider.setUserDetailsService(kerberosPrincipal -> {
                log.debug("Kerberos ticket validated for principal: {}. Wrapping in UserDetails.", kerberosPrincipal);
                // We MUST use lowercase here to match what the SuccessHandler will use.
                return new User(kerberosPrincipal.toLowerCase(), "N/A", true, true, true, true,
                        List.of(new SimpleGrantedAuthority("ROLE_PRE_AUTH")));
            });
            // --- END FIX ---

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
     * Helper method to create a temporary keytab file from Base64 data
     */
    private File createTempKeytab(String base64Keytab, Long tenantId) throws Exception {
        byte[] keytabBytes = Base64.getDecoder().decode(base64Keytab);

        Path tempPath = Files.createTempFile("kerberos-tenant-" + tenantId + "-", ".keytab");
        Files.write(tempPath, keytabBytes);

        File keytabFile = tempPath.toFile();
        keytabFile.deleteOnExit();

        try {
            keytabFile.setReadable(false, false);
            keytabFile.setReadable(true, true);
            keytabFile.setWritable(false, false);
            keytabFile.setWritable(true, true);
        } catch (Exception e) {
            log.warn("Could not set restrictive file permissions on temp keytab: {}", e.getMessage());
        }

        log.info("Created temporary keytab file for tenant {}: {}", tenantId, tempPath);
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