package com.example.ssoauth.entity;

public enum SsoProviderType {
    OIDC,
    JWT,
    SAML,
    KERBEROS  // NEW: Add Kerberos/SPNEGO authentication
}