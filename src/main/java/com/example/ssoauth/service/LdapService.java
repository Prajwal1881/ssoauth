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
import java.util.Hashtable;

@Service
@Slf4j
public class LdapService {

    public LdapUser authenticate(SsoProviderConfig config, String username, String password) {
        if (!StringUtils.hasText(password)) {
            throw new SSOAuthenticationException("Password cannot be empty");
        }

        // 1. Configure Initial Environment (Admin Bind)
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
            // 2. Connect as Admin
            ctx = new InitialDirContext(env);

            // 3. Search for the User
            String searchFilter = config.getLdapUserSearchFilter().replace("{0}", username);
            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            searchControls.setReturningAttributes(new String[]{"dn", "cn", "sn", "givenName", "mail", "sAMAccountName", "userPrincipalName"});

            NamingEnumeration<SearchResult> results = ctx.search(config.getLdapSearchBase(), searchFilter, searchControls);

            if (!results.hasMore()) {
                throw new SSOAuthenticationException("User not found in Directory");
            }

            SearchResult result = results.next();
            String userDn = result.getNameInNamespace(); // Get the full DN
            Attributes attrs = result.getAttributes();

            // 4. Verify Password (Re-bind as User)
            // We create a NEW context with the User's DN and Password to verify credentials
            Hashtable<String, String> userEnv = new Hashtable<>(env);
            userEnv.put(Context.SECURITY_PRINCIPAL, userDn);
            userEnv.put(Context.SECURITY_CREDENTIALS, password);

            DirContext userCtx = null;
            try {
                userCtx = new InitialDirContext(userEnv); // This throws exception if password is wrong
            } catch (Exception e) {
                throw new SSOAuthenticationException("Invalid credentials (LDAP Bind failed)");
            } finally {
                if (userCtx != null) userCtx.close();
            }

            // 5. Extract Attributes
            String email = getAttributeValue(attrs, "mail");
            String firstName = getAttributeValue(attrs, "givenName");
            String lastName = getAttributeValue(attrs, "sn");
            String sAMAccountName = getAttributeValue(attrs, "sAMAccountName");
            String upn = getAttributeValue(attrs, "userPrincipalName");

            // Fallback for username if sAMAccountName is missing
            String finalUsername = StringUtils.hasText(sAMAccountName) ? sAMAccountName :
                    (StringUtils.hasText(upn) ? upn.split("@")[0] : username);

            // Fallback for email (Crucial for SSO mapping)
            if (!StringUtils.hasText(email)) {
                if (StringUtils.hasText(upn)) {
                    email = upn;
                } else {
                    // Fail hard or soft? Let's throw for now as email is usually required for unique mapping
                    throw new SSOAuthenticationException("User does not have an email address in AD");
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
            log.error("LDAP Authentication Error", e);
            throw new SSOAuthenticationException("LDAP Error: " + e.getMessage());
        } finally {
            if (ctx != null) {
                try { ctx.close(); } catch (Exception ex) { /* ignore */ }
            }
        }
    }

    private String getAttributeValue(Attributes attrs, String attributeId) throws Exception {
        if (attrs.get(attributeId) != null) {
            return (String) attrs.get(attributeId).get();
        }
        return null;
    }
}