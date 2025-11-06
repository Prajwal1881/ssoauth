package com.example.ssoauth.config;

import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.entity.SsoProviderType;
import com.example.ssoauth.service.SsoConfigService;
import com.example.ssoauth.util.CertificateUtils; // NEW IMPORT
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.stereotype.Component;

// REMOVED: Unused imports
import java.security.cert.X509Certificate;
import java.util.Iterator;
// REMOVED: Unused imports
import java.util.stream.Collectors;
// REMOVED: Unused imports

/**
 * Dynamically loads SAML 2.0 Relying Party configurations from the database.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DynamicRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository, Iterable<RelyingPartyRegistration> {

    private final SsoConfigService ssoConfigService;

    /**
     * Finds a SAML configuration by its registrationId (e.g., "saml_miniorange")
     * This is the main method Spring Security will call.
     */
    @Override
    public RelyingPartyRegistration findByRegistrationId(String registrationId) {
        log.debug("Attempting to find SAML config for registrationId: {}", registrationId);
        // SsoConfigService is tenant-aware
        return ssoConfigService.getConfigByProviderId(registrationId)
                .filter(config -> config.isEnabled() && config.getProviderType() == SsoProviderType.SAML)
                .map(this::convertConfigToRegistration)
                .orElse(null);
    }

    /**
     * Provides an iterator over all enabled SAML configurations.
     */
    @Override
    public Iterator<RelyingPartyRegistration> iterator() {
        // SsoConfigService is tenant-aware
        return ssoConfigService.getAllConfigEntities().stream()
                .filter(config -> config.isEnabled() && config.getProviderType() == SsoProviderType.SAML)
                .map(this::convertConfigToRegistration)
                .collect(Collectors.toList())
                .iterator();
    }

    /**
     * Helper method to convert our SsoProviderConfig entity into a Spring Security
     * RelyingPartyRegistration object.
     */
    private RelyingPartyRegistration convertConfigToRegistration(SsoProviderConfig config) {
        log.info("Building SAML RelyingPartyRegistration for: {}", config.getProviderId());
        try {
            // 1. Load the SAML signing certificate (Using new utility class)
            X509Certificate idpCertificate = CertificateUtils.parseCertificate(config.getSamlCertificate());

            // 2. Create the SAML credential
            Saml2X509Credential credential = Saml2X509Credential.verification(idpCertificate);

            // 3. Build the RelyingPartyRegistration
            return RelyingPartyRegistration.withRegistrationId(config.getProviderId())
                    // Our (Service Provider) details
                    .entityId("{baseUrl}/saml2/service-provider-metadata/{registrationId}")
                    .assertionConsumerServiceLocation("{baseUrl}/login/saml2/sso/{registrationId}")

                    // Their (Identity Provider) details
                    .assertingPartyDetails(party -> party
                            .entityId(config.getSamlEntityId())
                            .singleSignOnServiceLocation(config.getSamlSsoUrl())
                            .verificationX509Credentials(c -> c.add(credential))

                            // *** --- THIS IS THE FIX --- ***
                            // This method belongs inside the assertingPartyDetails block
                            .wantAuthnRequestsSigned(false)
                    )
                    // *** --- MOVED FROM HERE --- ***
                    .build();

        } catch (Exception e) {
            log.error("Failed to configure SAML provider '{}': {}", config.getProviderId(), e.getMessage(), e);
            return null; // This provider will be disabled
        }
    }

    // REMOVED: parseCertificate method (moved to CertificateUtils)
}