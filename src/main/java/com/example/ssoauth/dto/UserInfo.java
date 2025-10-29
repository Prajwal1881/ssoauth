package com.example.ssoauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserInfo {

    private Long id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private String authProvider;
    private String roles; // Added roles field
}