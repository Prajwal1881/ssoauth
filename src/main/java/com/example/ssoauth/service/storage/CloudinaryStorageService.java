package com.example.ssoauth.service.storage;

import com.cloudinary.Cloudinary;
import com.cloudinary.Transformation;
import com.cloudinary.utils.ObjectUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

@Service
@Profile("cloud")
@RequiredArgsConstructor
@Slf4j
public class CloudinaryStorageService implements StorageService {

    private final Cloudinary cloudinary;

    private static final Set<String> ALLOWED_EXTENSIONS =
            Set.of("jpg", "jpeg", "png", "gif", "ico", "svg", "webp");

    @Override
    @SuppressWarnings("unchecked")
    public UploadResult uploadLogo(MultipartFile file, Long tenantId) throws IOException {
        validateFile(file);
        Map<String, Object> result = cloudinary.uploader().upload(file.getBytes(),
                ObjectUtils.asMap(
                        "folder",     "tenant-assets/" + tenantId + "/logos",
                        "public_id",  "logo",
                        "overwrite",  true,
                        "transformation", new Transformation()
                                .width(400).height(200).crop("limit")
                                .chain().quality("auto:good")
                                .chain().fetchFormat("auto")
                ));

        String url = (String) result.get("secure_url");
        log.info("Logo uploaded to Cloudinary for tenantId={}: {}", tenantId, url);
        return new UploadResult(url, url);
    }

    @Override
    @SuppressWarnings("unchecked")
    public UploadResult uploadFavicon(MultipartFile file, Long tenantId) throws IOException {
        validateFile(file);
        Map<String, Object> result = cloudinary.uploader().upload(file.getBytes(),
                ObjectUtils.asMap(
                        "folder",     "tenant-assets/" + tenantId + "/favicons",
                        "public_id",  "favicon",
                        "overwrite",  true,
                        "transformation", new Transformation()
                                .width(64).height(64).crop("fill")
                                .chain().quality("auto")
                                .chain().fetchFormat("auto")
                ));

        String url = (String) result.get("secure_url");
        log.info("Favicon uploaded to Cloudinary for tenantId={}: {}", tenantId, url);
        return new UploadResult(url, url);
    }

    @Override
    public String buildUrl(String storedPath) {
        // storedPath is the full Cloudinary URL; fall back gracefully for legacy on-prem paths
        if (storedPath == null) return null;
        if (!storedPath.startsWith("http://") && !storedPath.startsWith("https://")) {
            return "/uploads/" + storedPath;
        }
        return storedPath;
    }

    private void validateFile(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("File must not be empty");
        }
        String originalFilename = StringUtils.cleanPath(
                file.getOriginalFilename() != null ? file.getOriginalFilename() : "");
        int dotIdx = originalFilename.lastIndexOf('.');
        String ext = dotIdx >= 0 ? originalFilename.substring(dotIdx + 1).toLowerCase() : "";
        if (!ALLOWED_EXTENSIONS.contains(ext)) {
            throw new IllegalArgumentException(
                    "File type not allowed. Supported formats: jpg, jpeg, png, gif, ico, svg, webp");
        }
    }
}
