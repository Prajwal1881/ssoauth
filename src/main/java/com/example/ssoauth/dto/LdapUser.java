package com.example.ssoauth.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LdapUser {
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private String dn; // Distinguished Name
}