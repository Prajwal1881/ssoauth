package com.example.ssoauth.service;

import com.example.ssoauth.dto.ApiResponse;
import com.example.ssoauth.dto.SsoProviderConfigUpdateRequest;
import com.example.ssoauth.util.CertificateUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.naming.directory.DirContext;
import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;


@Service
@RequiredArgsConstructor
@Slf4j
public class SsoTestService {

    private final HttpClient httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_2)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    /**
     * Performs a static test on the provided SSO configuration without saving it.
     */
    public ApiResponse testConnection(SsoProviderConfigUpdateRequest config) {
        log.info("Testing connection for provider: {}", config.getProviderId());

        try {
            switch (config.getProviderType()) {
                case OIDC:
                    return testOidcConnection(config);
                case SAML:
                    return testSamlConnection(config);
                case JWT:
                    return testJwtConnection(config);
                case AD_LDAP:
                    return testLdapConnection(config);
                default:
                    return ApiResponse.builder().success(false).message("Unknown provider type").build();
            }
        } catch (Exception e) {
            log.error("Test connection failed: {}", e.getMessage());
            return ApiResponse.builder().success(false).message("Test failed: " + e.getMessage()).build();
        }
    }

    private ApiResponse testOidcConnection(SsoProviderConfigUpdateRequest config) {
        String testUrl = null;
        if (StringUtils.hasText(config.getJwkSetUri())) {
            testUrl = config.getJwkSetUri();
        } else if (StringUtils.hasText(config.getIssuerUri())) {
            // Try to discover from issuer
            testUrl = config.getIssuerUri() + "/.well-known/openid-configuration";
        }

        if (testUrl == null) {
            return ApiResponse.builder().success(false).message("No JWK Set URI or Issuer URI provided to test.")
                    .build();
        }

        return pingEndpoint(testUrl);
    }

    private ApiResponse testSamlConnection(SsoProviderConfigUpdateRequest config) {
        if (!StringUtils.hasText(config.getSamlCertificate())) {
            return ApiResponse.builder().success(false).message("SAML Certificate is missing.").build();
        }
        // The most common error is a bad certificate. Let's test parsing it.
        return testCertificate(config.getSamlCertificate(), "SAML");
    }

    private ApiResponse testJwtConnection(SsoProviderConfigUpdateRequest config) {
        if (!StringUtils.hasText(config.getJwtCertificate())) {
            return ApiResponse.builder().success(false).message("JWT Certificate is missing.").build();
        }
        return testCertificate(config.getJwtCertificate(), "JWT");
    }

    private ApiResponse testLdapConnection(SsoProviderConfigUpdateRequest config) {
        if (!StringUtils.hasText(config.getLdapServerUrl()) ||
                !StringUtils.hasText(config.getLdapBindDn()) ||
                !StringUtils.hasText(config.getLdapBindPassword())) {
            return ApiResponse.builder()
                    .success(false)
                    .message("Missing Server URL, Bind DN, or Password.")
                    .build();
        }

        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, config.getLdapServerUrl());
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, config.getLdapBindDn());
        env.put(Context.SECURITY_CREDENTIALS, config.getLdapBindPassword());

        // Force SSL if using ldaps
        if (config.getLdapServerUrl().toLowerCase().startsWith("ldaps://")) {
            env.put(Context.SECURITY_PROTOCOL, "ssl");
        }

        try {
            // Attempt to create the initial context (Binding)
            DirContext ctx = new InitialDirContext(env);
            ctx.close();
            return ApiResponse.builder()
                    .success(true)
                    .message("Successfully connected and bound to LDAP server.")
                    .build();
        } catch (Exception e) {
            log.error("LDAP Test Failed: {}", e.getMessage());
            return ApiResponse.builder()
                    .success(false)
                    .message("Connection Failed: " + e.getMessage())
                    .build();
        }
    }

    // Helper to ping a URL
    private ApiResponse pingEndpoint(String url) {
        try {
            log.info("Attempting to connect to: {}", url);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(new URI(url))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                return ApiResponse.builder().success(true)
                        .message("Successfully connected to " + url + " (Status 200 OK).").build();
            } else {
                return ApiResponse.builder().success(false)
                        .message("Connected to " + url + ", but received non-200 status: " + response.statusCode())
                        .build();
            }
        } catch (Exception e) {
            log.error("Failed to connect to {}: {}", url, e.getMessage());
            return ApiResponse.builder().success(false).message("Failed to connect to " + url + ": " + e.getMessage())
                    .build();
        }
    }

    // Helper to test-parse a certificate
    private ApiResponse testCertificate(String certPem, String type) {
        try {
            CertificateUtils.parseCertificate(certPem);
            return ApiResponse.builder().success(true).message(type + " certificate was parsed successfully.").build();
        } catch (Exception e) {
            log.error("Failed to parse certificate: {}", e.getMessage());
            return ApiResponse.builder().success(false).message(type + " certificate is invalid: " + e.getMessage())
                    .build();
        }
    }
}