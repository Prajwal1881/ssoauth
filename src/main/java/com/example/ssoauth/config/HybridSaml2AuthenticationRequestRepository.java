package com.example.ssoauth.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.web.HttpSessionSaml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stores SAML AuthnRequests in both the HTTP session (standard) and an in-memory map (fallback).
 *
 * On the first SP-initiated SAML flow, the session ID can change between the AuthnRequest
 * being stored and the ACS callback arriving — causing the session lookup to miss. The
 * in-memory fallback matches the AuthnRequest by extracting the InResponseTo value directly
 * from the SAMLResponse POST body, making the flow reliable on first attempt.
 */
@Component
@Slf4j
public class HybridSaml2AuthenticationRequestRepository
        implements Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> {

    private final HttpSessionSaml2AuthenticationRequestRepository sessionDelegate =
            new HttpSessionSaml2AuthenticationRequestRepository();

    // requestId → saved AuthnRequest
    private final ConcurrentHashMap<String, AbstractSaml2AuthenticationRequest> memStore =
            new ConcurrentHashMap<>();

    @Override
    public AbstractSaml2AuthenticationRequest loadAuthenticationRequest(HttpServletRequest request) {
        AbstractSaml2AuthenticationRequest saved = sessionDelegate.loadAuthenticationRequest(request);
        if (saved != null) return saved;

        String inResponseTo = extractInResponseTo(request.getParameter("SAMLResponse"));
        if (inResponseTo != null) {
            AbstractSaml2AuthenticationRequest fallback = memStore.get(inResponseTo);
            if (fallback != null) {
                log.info("SAML AuthnRequest resolved from memory fallback (load): id={}", inResponseTo);
                return fallback;
            }
        }
        return null;
    }

    @Override
    public void saveAuthenticationRequest(AbstractSaml2AuthenticationRequest authRequest,
                                          HttpServletRequest request, HttpServletResponse response) {
        sessionDelegate.saveAuthenticationRequest(authRequest, request, response);
        memStore.put(authRequest.getId(), authRequest);
        log.debug("SAML AuthnRequest saved: id={}", authRequest.getId());
    }

    @Override
    public AbstractSaml2AuthenticationRequest removeAuthenticationRequest(HttpServletRequest request,
                                                                          HttpServletResponse response) {
        AbstractSaml2AuthenticationRequest saved = sessionDelegate.removeAuthenticationRequest(request, response);
        if (saved != null) {
            memStore.remove(saved.getId());
            log.debug("SAML AuthnRequest resolved from session: id={}", saved.getId());
            return saved;
        }

        // Session miss — fall back to in-memory lookup via InResponseTo in the SAMLResponse body
        String inResponseTo = extractInResponseTo(request.getParameter("SAMLResponse"));
        if (inResponseTo != null) {
            AbstractSaml2AuthenticationRequest fallback = memStore.remove(inResponseTo);
            if (fallback != null) {
                log.debug("SAML AuthnRequest resolved from memory fallback: id={}", inResponseTo);
                return fallback;
            }
        }

        log.warn("SAML AuthnRequest not found in session or memory for ACS request");
        return null;
    }

    private String extractInResponseTo(String base64SamlResponse) {
        if (base64SamlResponse == null) return null;
        try {
            String xml = new String(Base64.getDecoder().decode(base64SamlResponse), StandardCharsets.UTF_8);
            int idx = xml.indexOf("InResponseTo=\"");
            if (idx < 0) return null;
            idx += 14;
            int end = xml.indexOf('"', idx);
            return (end > idx) ? xml.substring(idx, end) : null;
        } catch (Exception e) {
            log.debug("Could not extract InResponseTo from SAMLResponse", e);
            return null;
        }
    }
}
