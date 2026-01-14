package com.example.ssoauth.controller;

import com.example.ssoauth.service.TacacsService;
import com.example.ssoauth.service.AdminService; // To check tenant setting
import com.example.ssoauth.entity.Tenant; // If needed, or use DTO
import com.example.ssoauth.repository.TenantRepository; // Better to use repo to get raw functionality
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Controller
@RequestMapping("/virtual-router")
@RequiredArgsConstructor
@Slf4j
public class VirtualRouterController {

    private final TacacsService tacacsService;
    private final TenantRepository tenantRepository; // Direct repo access for simplicity in demo
    // In a real app, use a Service layer that checks TenantContext

    @GetMapping("/login")
    public String showLoginPage(Model model) {
        return "virtual-router-login";
    }

    @PostMapping("/login")
    public String processLogin(
            @RequestParam String host,
            @RequestParam int port,
            @RequestParam String secret,
            @RequestParam String username,
            @RequestParam String password,
            HttpSession session,
            Model model) {

        // 1. Authenticate against TACACS+
        boolean isAuthenticated = tacacsService.authenticate(host, port, secret, username, password);

        if (isAuthenticated) {
            // 2. Store details in Session for subsequent command checks
            session.setAttribute("vr_host", host);
            session.setAttribute("vr_port", port);
            session.setAttribute("vr_secret", secret);
            session.setAttribute("vr_username", username);
            session.setAttribute("vr_authenticated", true);

            return "redirect:/virtual-router/terminal";
        } else {
            model.addAttribute("error", "TACACS+ Authentication Failed");
            // Retain submitted values
            model.addAttribute("host", host);
            model.addAttribute("port", port);
            model.addAttribute("secret", secret);
            model.addAttribute("username", username);
            return "virtual-router-login";
        }
    }

    @GetMapping("/terminal")
    public String showTerminalPage(HttpSession session) {
        if (session.getAttribute("vr_authenticated") == null) {
            return "redirect:/virtual-router/login";
        }
        return "virtual-router-terminal";
    }

    @PostMapping("/command")
    @ResponseBody
    public ResponseEntity<String> executeCommand(@RequestBody Map<String, String> payload, HttpSession session) {
        if (session.getAttribute("vr_authenticated") == null) {
            return ResponseEntity.status(401).body("Unauthorized");
        }

        String command = payload.get("command");
        String host = (String) session.getAttribute("vr_host");
        int port = (int) session.getAttribute("vr_port");
        String secret = (String) session.getAttribute("vr_secret");
        String username = (String) session.getAttribute("vr_username");

        // 1. Authorize Command
        boolean isAuthorized = tacacsService.authorize(host, port, secret, username, command);

        if (isAuthorized) {
            // 2. Simulate Router Behavior
            return ResponseEntity.ok(simulateRouterResponse(command));
        } else {
            return ResponseEntity.ok("Command authorization failed.\r\n");
        }
    }

    private String simulateRouterResponse(String command) {
        if (command == null || command.trim().isEmpty())
            return "";

        String cleanCmd = command.trim();
        StringBuilder sb = new StringBuilder();
        sb.append(cleanCmd).append("\r\n"); // Echo command logic handled by terminal usually, but here checking
                                            // response

        if (cleanCmd.equalsIgnoreCase("show running-config")) {
            sb.append("Building configuration...\r\n");
            sb.append("Current configuration : 1024 bytes\r\n");
            sb.append("!\r\n");
            sb.append("version 16.9\r\n");
            sb.append("hostname VirtualRouter\r\n");
            sb.append("!\r\n");
            sb.append("interface GigabitEthernet1\r\n");
            sb.append(" ip address 192.168.1.1 255.255.255.0\r\n");
            sb.append("!\r\n");
            sb.append("end\r\n");
        } else if (cleanCmd.equalsIgnoreCase("show version")) {
            sb.append("Cisco IOS Software, VirtualRouter Software (X86_64_LINUX_IOSD-UNIVERSALK9-M)\r\n");
            sb.append("Version 16.9.4, RELEASE SOFTWARE (fc2)\r\n");
            sb.append("Uptime is 1 week, 4 days, 2 hours, 12 minutes\r\n");
        } else if (cleanCmd.equalsIgnoreCase("?")) {
            sb.append("Exec commands:\r\n");
            sb.append("  show       Show running system information\r\n");
            sb.append("  enable     Turn on privileged commands\r\n");
            sb.append("  configure  Enter configuration mode\r\n");
        } else {
            sb.append("% Invalid input detected at '^' marker.\r\n");
        }
        return sb.toString();
    }
}
