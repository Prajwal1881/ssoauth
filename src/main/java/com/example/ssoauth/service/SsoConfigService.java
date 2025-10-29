package com.example.ssoauth.service;

import com.example.ssoauth.dto.SsoProviderConfigDto;
import com.example.ssoauth.dto.SsoProviderConfigUpdateRequest;
import com.example.ssoauth.entity.SsoProviderConfig;
import com.example.ssoauth.repository.SsoProviderConfigRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.Optional;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class SsoConfigService {

    private final SsoProviderConfigRepository configRepository;

    // Get all configurations (for admin list)
    public List<SsoProviderConfigDto> getAllConfigs() {
        log.info("Fetching all SSO provider configurations");
        return configRepository.findAll().stream()
                .map(this::mapEntityToDto)
                .collect(Collectors.toList());
    }

    // Get a specific config by ID (for editing)
    public SsoProviderConfigDto getConfigById(Long id) {
        log.info("Fetching SSO config by ID: {}", id);
        SsoProviderConfig config = configRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("SSO Config not found with ID: " + id));
        return mapEntityToDto(config);
    }

    // Get a specific config by Provider ID (useful internally)
    public Optional<SsoProviderConfig> getConfigByProviderId(String providerId) {
        log.debug("Fetching SSO config by provider ID: {}", providerId);
        return configRepository.findByProviderId(providerId);
    }


    // Update an existing configuration
    @Transactional
    public SsoProviderConfigDto updateConfig(Long id, SsoProviderConfigUpdateRequest dto) {
        log.info("Updating SSO config for ID: {}", id);
        SsoProviderConfig existingConfig = configRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("SSO Config not found with ID: " + id));

        // Basic validation - ensure providerId/Type aren't changed via update
        if (!existingConfig.getProviderId().equals(dto.getProviderId()) ||
                !existingConfig.getProviderType().equals(dto.getProviderType())) {
            log.warn("Attempted to change providerId or providerType during update for ID: {}", id);
            throw new IllegalArgumentException("Provider ID and Type cannot be changed.");
        }

        // Copy properties from DTO to entity (excluding ID, createdAt, updatedAt)
        // Be careful with BeanUtils in production - consider explicit mapping or MapStruct
        BeanUtils.copyProperties(dto, existingConfig, "id", "createdAt", "updatedAt");

        // Explicitly handle potentially sensitive or null fields if BeanUtils isn't precise enough
        // existingConfig.setClientSecret(dto.getClientSecret()); // Example

        SsoProviderConfig updatedConfig = configRepository.save(existingConfig);
        log.info("SSO config updated successfully for ID: {}", id);
        return mapEntityToDto(updatedConfig);
    }

    // Get IDs of enabled providers (for login page)
    public List<String> getEnabledProviderIds() {
        log.debug("Fetching enabled SSO provider IDs");
        return configRepository.findByEnabledTrue().stream()
                .map(SsoProviderConfig::getProviderId)
                .collect(Collectors.toList());
    }

    // Mapper helper
    private SsoProviderConfigDto mapEntityToDto(SsoProviderConfig entity) {
        SsoProviderConfigDto dto = new SsoProviderConfigDto();
        // Copy properties, potentially excluding sensitive ones like clientSecret
        BeanUtils.copyProperties(entity, dto, "clientSecret"); // Example: Exclude secret
        // dto.setClientSecret(null); // Explicitly nullify if needed
        return dto;
    }

    // CREATE method (Optional - Usually configs are predefined)
    @Transactional
    public SsoProviderConfigDto createConfig(SsoProviderConfigUpdateRequest dto) {
        log.info("Creating new SSO config for provider ID: {}", dto.getProviderId());
        if (configRepository.existsByProviderId(dto.getProviderId())) {
            throw new IllegalArgumentException("Provider ID already exists: " + dto.getProviderId());
        }
        SsoProviderConfig newConfig = new SsoProviderConfig();
        BeanUtils.copyProperties(dto, newConfig, "id", "createdAt", "updatedAt");

        SsoProviderConfig savedConfig = configRepository.save(newConfig);
        log.info("SSO config created successfully with ID: {}", savedConfig.getId());
        return mapEntityToDto(savedConfig);
    }
}