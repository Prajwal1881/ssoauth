package com.example.ssoauth.security;

import com.example.ssoauth.config.TenantContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Enumeration;

@Component
@Slf4j
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        String errorMessage = "Authentication failed";
        Long tenantId = TenantContext.getCurrentTenant();

        // Enhanced logging for debugging
        log.error("=== OAuth2 Authentication Failure ===");
        log.error("Tenant ID: {}", tenantId);
        log.error("Request URI: {}", request.getRequestURI());
        log.error("Request URL: {}", request.getRequestURL());
        log.error("Server Name: {}", request.getServerName());

        // Log session information
        HttpSession session = request.getSession(false);
        if (session != null) {
            log.error("Session ID: {}", session.getId());
            log.error("Session Creation Time: {}", new java.util.Date(session.getCreationTime()));
            log.error("Session Last Accessed: {}", new java.util.Date(session.getLastAccessedTime()));

            // Log session attributes (excluding sensitive Spring Security ones)
            log.error("Session Attributes:");
            Enumeration<String> attrNames = session.getAttributeNames();
            while (attrNames.hasMoreElements()) {
                String attrName = attrNames.nextElement();
                if (!attrName.contains("SPRING_SECURITY") && !attrName.contains("AUTHORIZATION")) {
                    Object attrValue = session.getAttribute(attrName);
                    log.error("  {} = {}", attrName, attrValue);
                }
            }
        } else {
            log.error("NO ACTIVE SESSION - This is likely the root cause!");
        }

        if (exception instanceof OAuth2AuthenticationException) {
            OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();
            log.error("OAuth2 Error Code: [{}]", error.getErrorCode());
            log.error("OAuth2 Error Description: [{}]", error.getDescription());
            log.error("OAuth2 Error URI: [{}]", error.getUri());
            errorMessage = error.getErrorCode();

            // Provide specific guidance for common errors
            if ("authorization_request_not_found".equals(error.getErrorCode())) {
                log.error("⚠️ DIAGNOSIS: The OAuth2 authorization request was not found in the session.");
                log.error("   Possible causes:");
                log.error("   1. Session was invalidated between authorization and callback");
                log.error("   2. User switched tenants during OAuth2 flow");
                log.error("   3. Session cookie is not being sent properly");
                log.error("   4. Registration ID mismatch between start and callback");
            } else if ("invalid_state_parameter".equals(error.getErrorCode())) {
                log.error("⚠️ DIAGNOSIS: State parameter validation failed.");
                log.error("   This usually indicates a CSRF attack or session issue.");
            }
        } else {
            log.error("Non-OAuth2 Authentication Failure: {}", exception.getMessage(), exception);
        }

        log.error("======================================");

        // Redirect with specific error code for debugging
        setDefaultFailureUrl("/login?error=" + errorMessage);
        super.onAuthenticationFailure(request, response, exception);
    }
}