package com.example.ssoauth.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        String errorMessage = "Authentication failed";

        if (exception instanceof OAuth2AuthenticationException) {
            OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();
            log.error("OAuth2 Failure: Code=[{}], Description=[{}]", error.getErrorCode(), error.getDescription());
            errorMessage = error.getErrorCode(); // e.g., "invalid_grant" or "authorization_request_not_found"
        } else {
            log.error("Authentication Failure: {}", exception.getMessage());
        }

        // Redirect with specific error code for debugging
        setDefaultFailureUrl("/login?error=" + errorMessage);
        super.onAuthenticationFailure(request, response, exception);
    }
}