package com.example.ssoauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class SsoauthApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsoauthApplication.class, args);
    }
}
