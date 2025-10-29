package com.example.ssoauth.repository;

import com.example.ssoauth.entity.SsoProviderConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SsoProviderConfigRepository extends JpaRepository<SsoProviderConfig, Long> {

    List<SsoProviderConfig> findByEnabledTrue();

    Optional<SsoProviderConfig> findByProviderId(String providerId);

    boolean existsByProviderId(String providerId);
}