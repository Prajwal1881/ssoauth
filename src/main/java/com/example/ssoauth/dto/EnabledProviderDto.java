package com.example.ssoauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EnabledProviderDto {
    /**
     * The unique ID for this provider (e.g., "acme-oidc").
     */
    private String providerId;

    /**
     * The friendly name to display on the button (e.g., "Login with Okta").
     */
    private String displayName;

    /**
     * The fully constructed URL the button should link to.
     */
    private String ssoUrl;
}