package com.example.ssoauth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@Service
@Slf4j
public class JwtValidatorService {

    @Value("${miniorange.jwt.certificate.path}")
    private String certificatePath;

    @Value("${miniorange.jwt.client.id}")
    private String expectedIssuer;

    private final ResourceLoader resourceLoader;
    private PublicKey publicKey;

    public JwtValidatorService(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    /**
     * This method runs at startup to load the certificate
     * from the file specified in application.properties.
     */
    @PostConstruct
    public void init() {
        try {
            log.info("Loading JWT signing certificate from: {}", certificatePath);
            Resource resource = resourceLoader.getResource(certificatePath);
            InputStream inputStream = resource.getInputStream();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(inputStream);
            this.publicKey = certificate.getPublicKey();
            log.info("Successfully loaded JWT signing certificate. Algorithm: {}", this.publicKey.getAlgorithm());
        } catch (Exception e) {
            log.error("Failed to load JWT signing certificate: {}", certificatePath, e);
            throw new RuntimeException("Could not initialize JwtValidatorService: " + e.getMessage(), e);
        }
    }

    /**
     * Validates the JWT from miniOrange.
     * Throws an exception if the token is invalid.
     * Returns the claims if successful.
     */
    public Claims validateAndParseToken(String token) {
        if (this.publicKey == null) {
            throw new IllegalStateException("JWT signing key is not available. Check certificate loading.");
        }

        return Jwts.parserBuilder()
                .setSigningKey(this.publicKey) // Use the public key from the .cer file
                .requireIssuer(this.expectedIssuer) // Check the 'iss' claim
                .setAllowedClockSkewSeconds(5) // !!! ADDED: Allows up to 5 seconds clock skew !!!
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}