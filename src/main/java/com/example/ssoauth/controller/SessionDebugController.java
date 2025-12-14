package com.example.ssoauth.controller;

import com.example.ssoauth.config.TenantContext;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

/**
 * Debug endpoint to help diagnose session and tenant issues.
 * Remove this in production or secure it appropriately.
 */
@RestController
@RequestMapping("/api/debug")
@Slf4j
public class SessionDebugController {

    @GetMapping("/session-info")
    public ResponseEntity<Map<String, Object>> getSessionInfo(HttpServletRequest request) {
        Map<String, Object> info = new HashMap<>();

        // Current tenant
        Long tenantId = TenantContext.getCurrentTenant();
        info.put("currentTenant", tenantId);

        // Host information
        info.put("serverName", request.getServerName());
        info.put("requestURI", request.getRequestURI());

        // Session information
        HttpSession session = request.getSession(false);
        if (session != null) {
            info.put("sessionId", session.getId());
            info.put("sessionCreationTime", new Date(session.getCreationTime()));
            info.put("sessionLastAccessedTime", new Date(session.getLastAccessedTime()));
            info.put("sessionMaxInactiveInterval", session.getMaxInactiveInterval());

            // Session attributes
            Map<String, Object> attributes = new HashMap<>();
            Enumeration<String> attrNames = session.getAttributeNames();
            while (attrNames.hasMoreElements()) {
                String attrName = attrNames.nextElement();
                Object attrValue = session.getAttribute(attrName);

                // Sanitize sensitive data
                if (attrName.contains("SPRING_SECURITY") || attrName.contains("AUTHORIZATION")) {
                    attributes.put(attrName, "[REDACTED - Spring Security Data]");
                } else {
                    attributes.put(attrName, attrValue != null ? attrValue.toString() : "null");
                }
            }
            info.put("sessionAttributes", attributes);
        } else {
            info.put("session", "No active session");
        }

        // Cookie information
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            List<Map<String, String>> cookieList = new ArrayList<>();
            for (Cookie cookie : cookies) {
                Map<String, String> cookieInfo = new HashMap<>();
                cookieInfo.put("name", cookie.getName());
                cookieInfo.put("domain", cookie.getDomain());
                cookieInfo.put("path", cookie.getPath());
                cookieInfo.put("maxAge", String.valueOf(cookie.getMaxAge()));
                cookieInfo.put("secure", String.valueOf(cookie.getSecure()));
                cookieInfo.put("httpOnly", String.valueOf(cookie.isHttpOnly()));
                // Don't include actual cookie value for security
                cookieList.add(cookieInfo);
            }
            info.put("cookies", cookieList);
        } else {
            info.put("cookies", "No cookies");
        }

        return ResponseEntity.ok(info);
    }

    @GetMapping("/clear-session")
    public ResponseEntity<String> clearSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            String oldSessionId = session.getId();
            session.invalidate();
            log.info("Session invalidated: {}", oldSessionId);
            return ResponseEntity.ok("Session cleared: " + oldSessionId);
        }
        return ResponseEntity.ok("No active session to clear");
    }
}