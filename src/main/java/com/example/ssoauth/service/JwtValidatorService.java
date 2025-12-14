package com.example.ssoauth.service;

import com.example.ssoauth.util.CertificateUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys; // Import for HMAC keys
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.Key;
@Service
@Slf4j
public class JwtValidatorService {
    /**
     * Validates an external JWT using a dynamically provided certificate and expected issuer.
     * Throws an exception if the token is invalid.
     * Returns the claims if successful.

     * Validates an external JWT using either a Certificate (RS256) or a Client Secret (HS256).
     * * @param token The JWT string
     * @param certificatePem The PEM certificate string (for RS256)
     * @param clientSecret The client secret string (for HS256)
     * @param expectedIssuer The expected issuer (iss claim)
     * @return The parsed Claims
     */
    public Claims validateAndParseToken(String token, String certificatePem, String clientSecret, String expectedIssuer, String algorithm) {

        // Default to RS256 if null
        String algo = StringUtils.hasText(algorithm) ? algorithm : "RS256";
        Key key;

        if ("HS256".equalsIgnoreCase(algo)) {
            // --- HS256 Validation ---
            if (!StringUtils.hasText(clientSecret)) {
                throw new IllegalArgumentException("HS256 algorithm requires a Client Secret.");
            }
            if (clientSecret.length() < 32) {
                throw new IllegalArgumentException("HS256 Client Secret must be at least 32 characters long for security.");
            }
            log.debug("Validating JWT using HS256 (Client Secret)");
            key = Keys.hmacShaKeyFor(clientSecret.getBytes(StandardCharsets.UTF_8));

        } else {
            // --- RS256 Validation (Default) ---
            if (!StringUtils.hasText(certificatePem)) {
                throw new IllegalArgumentException("RS256 algorithm requires a valid X.509 Certificate.");
            }
            log.debug("Validating JWT using RS256 (Certificate)");
            try {
                key = CertificateUtils.getPublicKeyFromPem(certificatePem);
            } catch (Exception e) {
                throw new IllegalArgumentException("Failed to parse Certificate: " + e.getMessage());
            }
        }

        return Jwts.parserBuilder()
                .setSigningKey(key)
                .requireIssuer(expectedIssuer)
                .setAllowedClockSkewSeconds(30)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}