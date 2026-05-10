package com.example.ssoauth.service.storage;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Set;

@Service
@Profile("onprem")
@Slf4j
public class LocalStorageService implements StorageService {

    @Value("${app.upload.dir:./uploads}")
    private String uploadDir;

    private static final Set<String> ALLOWED_EXTENSIONS =
            Set.of("jpg", "jpeg", "png", "gif", "ico", "svg", "webp");

    @Override
    public UploadResult uploadLogo(MultipartFile file, Long tenantId) throws IOException {
        String relPath = save(file, tenantId, "logo");
        return new UploadResult(relPath, "/uploads/" + relPath);
    }

    @Override
    public UploadResult uploadFavicon(MultipartFile file, Long tenantId) throws IOException {
        String relPath = save(file, tenantId, "favicon");
        return new UploadResult(relPath, "/uploads/" + relPath);
    }

    @Override
    public String buildUrl(String storedPath) {
        if (storedPath == null) return null;
        if (storedPath.startsWith("http://") || storedPath.startsWith("https://")) {
            return storedPath;
        }
        return "/uploads/" + storedPath;
    }

    private String save(MultipartFile file, Long tenantId, String baseName) throws IOException {
        String originalFilename = StringUtils.cleanPath(
                file.getOriginalFilename() != null ? file.getOriginalFilename() : "");
        if (originalFilename.isEmpty() || file.isEmpty()) {
            throw new IllegalArgumentException("File must not be empty");
        }

        int dotIdx = originalFilename.lastIndexOf('.');
        String ext = dotIdx >= 0 ? originalFilename.substring(dotIdx + 1).toLowerCase() : "";
        if (!ALLOWED_EXTENSIONS.contains(ext)) {
            throw new IllegalArgumentException(
                    "File type not allowed. Supported formats: jpg, jpeg, png, gif, ico, svg, webp");
        }

        Path baseUploadPath = Paths.get(uploadDir).toAbsolutePath().normalize();
        Path tenantDir = baseUploadPath.resolve("tenants").resolve(tenantId.toString());
        Files.createDirectories(tenantDir);

        String filename = baseName + "." + ext;
        Path targetPath = tenantDir.resolve(filename).normalize();

        if (!targetPath.startsWith(baseUploadPath)) {
            throw new SecurityException("Invalid file path");
        }

        Files.copy(file.getInputStream(), targetPath, StandardCopyOption.REPLACE_EXISTING);
        log.info("Saved {} for tenantId={} at {}", baseName, tenantId, targetPath);
        return "tenants/" + tenantId + "/" + filename;
    }
}
