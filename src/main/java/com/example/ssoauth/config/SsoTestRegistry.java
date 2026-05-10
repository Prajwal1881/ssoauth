package com.example.ssoauth.config;

import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Server-side registry for active SSO test flows.
 *
 * Replaces the HTTP session attribute approach for tracking which provider is under test.
 * Session attributes are unreliable across the SP→IdP→SP redirect chain (session fixation,
 * popup window edge cases). This registry survives those transitions.
 */
@Component
public class SsoTestRegistry {

    private static final long TTL_MS = 5 * 60 * 1000L; // 5 minutes

    // registrationId → expiry epoch ms
    private final ConcurrentHashMap<String, Long> activeTests = new ConcurrentHashMap<>();

    public void markAsTest(String registrationId) {
        activeTests.put(registrationId, System.currentTimeMillis() + TTL_MS);
    }

    public boolean isTest(String registrationId) {
        if (registrationId == null) return false;
        Long expiry = activeTests.get(registrationId);
        if (expiry == null) return false;
        if (System.currentTimeMillis() > expiry) {
            activeTests.remove(registrationId);
            return false;
        }
        return true;
    }

    /**
     * Checks whether any registered test provider ID is contained in the given registrationId.
     * Handles cases where the OIDC registration ID has a tenant suffix (e.g. "miniorange-50").
     */
    public boolean isTestContains(String registrationId) {
        if (registrationId == null) return false;
        long now = System.currentTimeMillis();
        return activeTests.entrySet().stream()
                .filter(e -> now <= e.getValue())
                .anyMatch(e -> registrationId.contains(e.getKey()));
    }

    public void complete(String registrationId) {
        activeTests.remove(registrationId);
    }
}
