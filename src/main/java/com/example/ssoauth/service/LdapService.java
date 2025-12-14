package com.example.ssoauth.service;

import com.example.ssoauth.dto.LdapUser;
import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.exception.SSOAuthenticationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.*;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

@Service
@Slf4j
public class LdapService {

    public LdapUser authenticate(SsoProviderConfig config, String username, String password) {
        if (!StringUtils.hasText(password)) {
            throw new SSOAuthenticationException("Password cannot be empty");
        }

        // 1. Setup Connection Environment
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, config.getLdapServerUrl());
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, config.getLdapBindDn());
        env.put(Context.SECURITY_CREDENTIALS, config.getLdapBindPassword());

        if (config.getLdapServerUrl().toLowerCase().startsWith("ldaps://")) {
            env.put(Context.SECURITY_PROTOCOL, "ssl");
        }

        DirContext ctx = null;
        try {
            // 2. Connect (Bind) as Admin
            log.debug("Connecting to LDAP server: {}", config.getLdapServerUrl());
            ctx = new InitialDirContext(env);

            // 3. Prepare Search Filter
            String rawFilter = config.getLdapUserSearchFilter();
            if (!StringUtils.hasText(rawFilter)) {
                // Default robust filter
                rawFilter = "(&(objectClass=user)(|(sAMAccountName={0})(userPrincipalName={0})(mail={0})))";
            }

            // Handle both '{0}' and '?' as placeholders
            String searchFilter = rawFilter
                    .replace("{0}", escapeLdapSearchFilter(username))
                    .replace("?", escapeLdapSearchFilter(username));

            String searchBase = config.getLdapSearchBase();

            log.info("Searching LDAP | Base: '{}' | Filter: '{}'", searchBase, searchFilter);

            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            // Fetch standard attributes for mapping
            searchControls.setReturningAttributes(new String[]{"dn", "cn", "sn", "givenName", "mail", "sAMAccountName", "userPrincipalName", "displayName"});

            // 4. Execute Search
            NamingEnumeration<SearchResult> results = ctx.search(searchBase, searchFilter, searchControls);

            if (!results.hasMore()) {
                log.warn("User '{}' not found in directory with filter: {}", username, searchFilter);
                throw new SSOAuthenticationException("User not found in Directory");
            }

            SearchResult result = results.next();
            String userDn = result.getNameInNamespace();
            Attributes attrs = result.getAttributes();

            log.info("User found: {}", userDn);

            // 5. Verify Password (Re-bind as User)
            // We create a NEW context with the User's DN and Password to verify credentials
            Hashtable<String, String> userEnv = new Hashtable<>(env);
            userEnv.put(Context.SECURITY_PRINCIPAL, userDn);
            userEnv.put(Context.SECURITY_CREDENTIALS, password);

            DirContext userCtx = null;
            try {
                userCtx = new InitialDirContext(userEnv); // Throws exception if password is wrong
                log.info("User credentials verified successfully for: {}", userDn);
            } catch (Exception e) {
                log.warn("Invalid credentials for user: {}", userDn);
                throw new SSOAuthenticationException("Invalid credentials (LDAP Bind failed)");
            } finally {
                if (userCtx != null) try { userCtx.close(); } catch(Exception e) {}
            }

            // 6. Extract Attributes for User Profile
            String email = getAttributeValue(attrs, "mail");
            String firstName = getAttributeValue(attrs, "givenName");
            String lastName = getAttributeValue(attrs, "sn");
            String sAMAccountName = getAttributeValue(attrs, "sAMAccountName");
            String upn = getAttributeValue(attrs, "userPrincipalName");
            String displayName = getAttributeValue(attrs, "displayName");

            // Username Heuristic: Prefer sAMAccountName > UPN prefix > Input
            String finalUsername = username;
            if (StringUtils.hasText(sAMAccountName)) {
                finalUsername = sAMAccountName;
            } else if (StringUtils.hasText(upn)) {
                finalUsername = upn.split("@")[0];
            }

            // --- CRITICAL FIX: Normalize username to lowercase ---
            if (finalUsername != null) {
                finalUsername = finalUsername.toLowerCase();
            }

            // Email Heuristic (Crucial for SSO)
            if (!StringUtils.hasText(email)) {
                if (StringUtils.hasText(upn)) {
                    email = upn;
                } else {
                    // Generate placeholder if missing to allow login to proceed
                    log.warn("No 'mail' attribute found for user {}. Using placeholder.", finalUsername);
                    email = finalUsername + "@" + config.getTenant().getSubdomain() + ".local";
                }
            }

            // Name Heuristic
            if (!StringUtils.hasText(firstName) && StringUtils.hasText(displayName)) {
                String[] parts = displayName.split(" ");
                firstName = parts[0];
                if (parts.length > 1 && !StringUtils.hasText(lastName)) {
                    lastName = parts[parts.length - 1];
                }
            }

            return LdapUser.builder()
                    .username(finalUsername)
                    .email(email)
                    .firstName(firstName)
                    .lastName(lastName)
                    .dn(userDn)
                    .build();

        } catch (SSOAuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("LDAP System Error", e);
            throw new SSOAuthenticationException("LDAP Error: " + e.getMessage());
        } finally {
            if (ctx != null) {
                try { ctx.close(); } catch (Exception ex) { /* ignore */ }
            }
        }
    }

    /**
     * Connects to AD and fetches ALL users matching the filter in the search base.
     */
    public List<LdapUser> listUsers(SsoProviderConfig config) {
        List<LdapUser> users = new ArrayList<>();

        // 1. Setup Environment
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, config.getLdapServerUrl());
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, config.getLdapBindDn());
        env.put(Context.SECURITY_CREDENTIALS, config.getLdapBindPassword());

        if (config.getLdapServerUrl().toLowerCase().startsWith("ldaps://")) {
            env.put(Context.SECURITY_PROTOCOL, "ssl");
        }

        DirContext ctx = null;
        try {
            // 2. Connect
            log.info("Connecting to LDAP for Bulk Import: {}", config.getLdapServerUrl());
            ctx = new InitialDirContext(env);

            // 3. Configure Search
            String searchBase = config.getLdapSearchBase();

            // Use configured filter or default to all users
            String searchFilter = config.getLdapUserSearchFilter();
            if (!StringUtils.hasText(searchFilter)) {
                searchFilter = "(objectClass=user)";
            } else {
                // If filter has placeholders like {0} or ?, replace them with wildcard * for bulk fetch
                searchFilter = searchFilter.replace("{0}", "*").replace("?", "*");
            }

            log.info("Importing users from Base: '{}' with Filter: '{}'", searchBase, searchFilter);

            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            // Fetch standard attributes
            searchControls.setReturningAttributes(new String[]{"dn", "cn", "sn", "givenName", "mail", "sAMAccountName", "userPrincipalName", "displayName"});
            // Optional: Set count limit (e.g., 1000 is often AD default limit)
            searchControls.setCountLimit(2000);

            // 4. Search
            NamingEnumeration<SearchResult> results = ctx.search(searchBase, searchFilter, searchControls);

            while (results.hasMore()) {
                try {
                    SearchResult result = results.next();
                    Attributes attrs = result.getAttributes();
                    String userDn = result.getNameInNamespace();

                    // Reuse the extraction logic from authenticate() or duplicate it here safely
                    String email = getAttributeValue(attrs, "mail");
                    String firstName = getAttributeValue(attrs, "givenName");
                    String lastName = getAttributeValue(attrs, "sn");
                    String sAMAccountName = getAttributeValue(attrs, "sAMAccountName");
                    String upn = getAttributeValue(attrs, "userPrincipalName");
                    String displayName = getAttributeValue(attrs, "displayName");

                    // Username Logic
                    String finalUsername = sAMAccountName;
                    if (!StringUtils.hasText(finalUsername) && StringUtils.hasText(upn)) {
                        finalUsername = upn.split("@")[0];
                    }
                    if (!StringUtils.hasText(finalUsername)) continue; // Skip if no identifier

                    // --- CRITICAL FIX: Normalize username to lowercase ---
                    if (finalUsername != null) {
                        finalUsername = finalUsername.toLowerCase();
                    }

                    // Email Logic (Skip if no email, or generate placeholder?)
                    // For import, we usually only want valid users. Let's skip if no email.
                    if (!StringUtils.hasText(email)) {
                        if (StringUtils.hasText(upn)) {
                            email = upn;
                        } else {
                            log.debug("Skipping user {} - no email found.", finalUsername);
                            continue;
                        }
                    }

                    // Name Logic
                    if (!StringUtils.hasText(firstName) && StringUtils.hasText(displayName)) {
                        String[] parts = displayName.split(" ");
                        firstName = parts[0];
                        if (parts.length > 1 && !StringUtils.hasText(lastName)) {
                            lastName = parts[parts.length - 1];
                        }
                    }

                    users.add(LdapUser.builder()
                            .username(finalUsername)
                            .email(email)
                            .firstName(firstName)
                            .lastName(lastName)
                            .dn(userDn)
                            .build());

                } catch (Exception e) {
                    log.warn("Error parsing single LDAP entry during import: {}", e.getMessage());
                }
            }
            log.info("Found {} users in AD.", users.size());

        } catch (Exception e) {
            log.error("LDAP Import Failed", e);
            throw new SSOAuthenticationException("Import Failed: " + e.getMessage());
        } finally {
            if (ctx != null) {
                try { ctx.close(); } catch (Exception ex) { }
            }
        }
        return users;
    }

    private String getAttributeValue(Attributes attrs, String attributeId) {
        try {
            if (attrs.get(attributeId) != null && attrs.get(attributeId).get() != null) {
                return attrs.get(attributeId).get().toString();
            }
        } catch (Exception e) {
            log.debug("Error fetching attribute {}", attributeId, e);
        }
        return null;
    }

    /**
     * Basic sanitization to prevent LDAP injection in the filter
     */
    private String escapeLdapSearchFilter(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char curChar = input.charAt(i);
            switch (curChar) {
                case '\\': sb.append("\\5c"); break;
                case '*': sb.append("\\2a"); break;
                case '(': sb.append("\\28"); break;
                case ')': sb.append("\\29"); break;
                case '\u0000': sb.append("\\00"); break;
                default: sb.append(curChar);
            }
        }
        return sb.toString();
    }
}