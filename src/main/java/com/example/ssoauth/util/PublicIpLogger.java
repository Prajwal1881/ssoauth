package com.example.ssoauth.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
@Slf4j
public class PublicIpLogger implements CommandLineRunner {

    @Override
    public void run(String... args) {
        try {
            RestTemplate restTemplate = new RestTemplate();
            String publicIp = restTemplate.getForObject("https://ifconfig.me/ip", String.class);
            log.info("=========================================");
            log.info("🌍 CURRENT PUBLIC IP ADDRESS: {}", publicIp);
            log.info("   (Whitelist this IP on your TACACS+ Server)");
            log.info("=========================================");
        } catch (Exception e) {
            log.warn("⚠️ Could not determine public IP: {}", e.getMessage());
        }
    }
}
