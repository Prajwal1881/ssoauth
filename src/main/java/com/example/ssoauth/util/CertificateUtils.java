package com.example.ssoauth.util;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Utility class for handling X.509 Certificates.
 */
public class CertificateUtils {

    /**
     * Converts a PEM certificate string into an X509Certificate object.
     */
    public static X509Certificate parseCertificate(String pemCertificate) {
        if (pemCertificate == null || pemCertificate.isEmpty()) {
            throw new IllegalArgumentException("Certificate is null or empty.");
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            try (InputStream certStream = new ByteArrayInputStream(pemCertificate.getBytes())) {
                return (X509Certificate) factory.generateCertificate(certStream);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse certificate: " + e.getMessage(), e);
        }
    }

    /**
     * Extracts the PublicKey from a PEM certificate string.
     */
    public static PublicKey getPublicKeyFromPem(String pemCertificate) {
        return parseCertificate(pemCertificate).getPublicKey();
    }
}