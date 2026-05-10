package com.example.ssoauth.service.storage;

/**
 * @param storedPath value persisted in the DB (relative path for onprem, full URL for cloud)
 * @param url        browser-accessible URL ready for API responses
 */
public record UploadResult(String storedPath, String url) {}
