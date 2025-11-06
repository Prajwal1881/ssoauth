package com.example.ssoauth.config;

import org.springframework.stereotype.Component;

@Component
public class TenantContext {

    // --- FIX: Store the Long ID, not the String subdomain ---
    private static final ThreadLocal<Long> currentTenantId = new ThreadLocal<>();

    public static void setCurrentTenant(Long tenantId) {
        currentTenantId.set(tenantId);
    }

    public static Long getCurrentTenant() {
        return currentTenantId.get();
    }

    public static void clear() {
        currentTenantId.remove();
    }
}