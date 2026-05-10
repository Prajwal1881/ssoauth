package com.example.ssoauth.service.storage;

import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

public interface StorageService {

    UploadResult uploadLogo(MultipartFile file, Long tenantId) throws IOException;

    UploadResult uploadFavicon(MultipartFile file, Long tenantId) throws IOException;

    /**
     * Converts the stored path/URL to a browser-accessible URL.
     * For onprem: prepends /uploads/ to relative paths.
     * For cloud: returns Cloudinary URL as-is.
     */
    String buildUrl(String storedPath);
}
