package com.example.ssoauth.service;

import com.example.ssoauth.util.CertificateUtils; // NEW IMPORT
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
// REMOVED: jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
// REMOVED: @Value
// REMOVED: Resource imports
import org.springframework.stereotype.Service;

// REMOVED: java.io.InputStream;
import java.security.PublicKey;
// REMOVED: Certificate imports

@Service
@Slf4j
public class JwtValidatorService {

    // REMOVED: All @Value properties
    // REMOVED: ResourceLoader
    // REMOVED: publicKey field
    // REMOVED: Constructor
    // REMOVED: init() method

    /**
     * Validates an external JWT using a dynamically provided certificate and expected issuer.
     * Throws an exception if the token is invalid.
     * Returns the claims if successful.
     */
    public Claims validateAndParseToken(String token, String certificatePem, String expectedIssuer) {

        // 1. Get Public Key from the PEM string
        PublicKey publicKey;
        try {
            publicKey = CertificateUtils.getPublicKeyFromPem(certificatePem);
            log.debug("Successfully parsed public key from PEM for issuer: {}", expectedIssuer);
        } catch (Exception e) {
            log.error("Failed to parse certificate PEM for issuer {}: {}", expectedIssuer, e.getMessage(), e);
            throw new IllegalStateException("JWT signing key is not available. Check certificate configuration.");
        }

        // 2. Validate the token using the dynamic key and issuer
        return Jwts.parserBuilder()
                .setSigningKey(publicKey) // Use the public key from the .cer file
                .requireIssuer(expectedIssuer) // Check the 'iss' claim
                .setAllowedClockSkewSeconds(30) // Increased skew for safety
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}