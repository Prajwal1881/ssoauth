// SSOAuthenticationException.java
package com.example.ssoauth.exception;

public class SSOAuthenticationException extends RuntimeException {
    public SSOAuthenticationException(String message) {
        super(message);
    }

    public SSOAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}