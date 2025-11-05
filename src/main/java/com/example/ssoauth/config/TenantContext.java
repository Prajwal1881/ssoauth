package com.example.ssoauth.config;

import org.springframework.stereotype.Component;

@Component
public class TenantContext {

    // --- FIX: Store the String subdomain, not the Long ID ---
    private static final ThreadLocal<String> currentTenantSubdomain = new ThreadLocal<>();

    public static void setCurrentTenant(String subdomain) {
        currentTenantSubdomain.set(subdomain);
    }

    public static String getCurrentTenant() {
        return currentTenantSubdomain.get();
    }

    public static void clear() {
        currentTenantSubdomain.remove();
    }
}