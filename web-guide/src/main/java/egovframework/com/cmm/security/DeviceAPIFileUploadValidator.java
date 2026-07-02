package egovframework.com.cmm.security;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

import org.springframework.web.multipart.MultipartFile;

import egovframework.rte.fdl.cmmn.exception.EgovBizException;

public final class DeviceAPIFileUploadValidator {

    private static final long MAX_FILE_SIZE_BYTES = 50L * 1024L * 1024L;
    private static final int HEADER_READ_SIZE = 16;

    private static final Set<String> FRW_EXTENSIONS = new HashSet<String>(Arrays.asList(
            "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", "jpg", "jpeg", "png", "gif", "mp4"));

    private static final Set<String> CMR_EXTENSIONS = new HashSet<String>(Arrays.asList(
            "jpg", "jpeg", "png", "gif"));

    private static final Set<String> MDA_EXTENSIONS = new HashSet<String>(Arrays.asList(
            "mp3", "mp4", "m4a", "wav", "3gp"));

    private static final Set<String> DANGEROUS_CONTENT_TYPES = new HashSet<String>(Arrays.asList(
            "application/x-php", "application/x-httpd-php", "text/php", "application/x-jsp",
            "application/javascript", "text/javascript", "text/html", "application/xhtml+xml",
            "application/x-msdownload", "application/x-sh", "application/x-executable"));

    private DeviceAPIFileUploadValidator() {
    }

    public static void validateFrwUpload(MultipartFile file) throws EgovBizException {
        validateUpload(file, FRW_EXTENSIONS, "frw");
    }

    public static void validateCmrUpload(MultipartFile file) throws EgovBizException {
        validateUpload(file, CMR_EXTENSIONS, "cmr");
    }

    public static void validateMdaUpload(MultipartFile file) throws EgovBizException {
        validateUpload(file, MDA_EXTENSIONS, "mda");
    }

    public static void assertSafeStoredFileName(String storedFileName) throws EgovBizException {
        if (storedFileName == null || storedFileName.trim().isEmpty()) {
            throw new EgovBizException("Stored file name is invalid.");
        }
        String trimmed = storedFileName.trim();
        if (trimmed.contains("..") || trimmed.contains("/") || trimmed.contains("\\") || trimmed.contains("\0")) {
            throw new EgovBizException("Stored file name is invalid.");
        }
    }

    private static void validateUpload(MultipartFile file, Set<String> allowedExtensions, String module)
            throws EgovBizException {
        if (file == null || file.isEmpty()) {
            throw new EgovBizException("Upload file is empty.");
        }
        if (file.getSize() > MAX_FILE_SIZE_BYTES) {
            throw new EgovBizException("Upload file exceeds allowed size.");
        }

        String originalFilename = file.getOriginalFilename();
        if (originalFilename == null || originalFilename.trim().isEmpty()) {
            throw new EgovBizException("Upload file name is missing.");
        }
        if (originalFilename.contains("..") || originalFilename.contains("/") || originalFilename.contains("\\")) {
            throw new EgovBizException("Upload file name is invalid.");
        }

        String extension = extractExtension(originalFilename);
        if (!allowedExtensions.contains(extension)) {
            throw new EgovBizException("Upload file extension is not allowed for " + module + ".");
        }

        validateContentType(file);
        validateMagicBytes(file, extension);
    }

    private static void validateContentType(MultipartFile file) throws EgovBizException {
        String contentType = file.getContentType();
        if (contentType == null || contentType.trim().isEmpty()) {
            return;
        }

        String normalized = contentType.toLowerCase(Locale.ENGLISH).split(";")[0].trim();
        if ("application/octet-stream".equals(normalized) || "binary/octet-stream".equals(normalized)) {
            return;
        }
        if (DANGEROUS_CONTENT_TYPES.contains(normalized)) {
            throw new EgovBizException("Upload content type is not allowed.");
        }
    }

    private static void validateMagicBytes(MultipartFile file, String extension) throws EgovBizException {
        try {
            byte[] header = readHeader(file, HEADER_READ_SIZE);
            rejectDangerousContent(header);

            if ("txt".equals(extension)) {
                return;
            }
            if (!matchesAllowedSignature(extension, header)) {
                throw new EgovBizException("Upload file content does not match the declared extension.");
            }
        } catch (IOException e) {
            throw new EgovBizException("Unable to inspect upload file content.");
        }
    }

    private static void rejectDangerousContent(byte[] header) throws EgovBizException {
        if (header.length >= 2 && header[0] == 'M' && header[1] == 'Z') {
            throw new EgovBizException("Executable upload is not allowed.");
        }
        if (header.length >= 4 && header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F') {
            throw new EgovBizException("Executable upload is not allowed.");
        }

        String prefix = new String(header, 0, Math.min(header.length, 12), StandardCharsets.US_ASCII)
                .toLowerCase(Locale.ENGLISH);
        if (prefix.contains("<?php") || prefix.contains("<%@") || prefix.startsWith("#!/")) {
            throw new EgovBizException("Script upload is not allowed.");
        }
    }

    private static boolean matchesAllowedSignature(String extension, byte[] header) {
        if ("jpg".equals(extension) || "jpeg".equals(extension)) {
            return header.length >= 3
                    && (header[0] & 0xFF) == 0xFF
                    && (header[1] & 0xFF) == 0xD8
                    && (header[2] & 0xFF) == 0xFF;
        }
        if ("png".equals(extension)) {
            return header.length >= 8
                    && header[0] == (byte) 0x89
                    && header[1] == 'P'
                    && header[2] == 'N'
                    && header[3] == 'G';
        }
        if ("gif".equals(extension)) {
            return startsWithAscii(header, "GIF87a") || startsWithAscii(header, "GIF89a");
        }
        if ("pdf".equals(extension)) {
            return startsWithAscii(header, "%PDF");
        }
        if ("zip".equals(extension)) {
            return isZipSignature(header);
        }
        if ("doc".equals(extension) || "xls".equals(extension) || "ppt".equals(extension)) {
            return header.length >= 8
                    && header[0] == (byte) 0xD0
                    && header[1] == (byte) 0xCF
                    && header[2] == 0x11
                    && header[3] == (byte) 0xE0;
        }
        if ("docx".equals(extension) || "xlsx".equals(extension) || "pptx".equals(extension)) {
            return isZipSignature(header);
        }
        if ("mp3".equals(extension)) {
            return startsWithAscii(header, "ID3")
                    || (header.length >= 2 && (header[0] & 0xFF) == 0xFF && (header[1] & 0xE0) == 0xE0)
                    || isIsoMediaSignature(header);
        }
        if ("wav".equals(extension)) {
            return header.length >= 12
                    && header[0] == 'R'
                    && header[1] == 'I'
                    && header[2] == 'F'
                    && header[3] == 'F'
                    && header[8] == 'W'
                    && header[9] == 'A'
                    && header[10] == 'V'
                    && header[11] == 'E';
        }
        if ("mp4".equals(extension) || "m4a".equals(extension) || "3gp".equals(extension)) {
            return isIsoMediaSignature(header);
        }
        return true;
    }

    private static boolean isIsoMediaSignature(byte[] header) {
        return header.length >= 8
                && header[4] == 'f'
                && header[5] == 't'
                && header[6] == 'y'
                && header[7] == 'p';
    }

    private static boolean isZipSignature(byte[] header) {
        return header.length >= 4 && header[0] == 'P' && header[1] == 'K' && header[2] == 3 && header[3] == 4;
    }

    private static boolean startsWithAscii(byte[] header, String value) {
        byte[] prefix = value.getBytes(StandardCharsets.US_ASCII);
        if (header.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (header[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    private static byte[] readHeader(MultipartFile file, int size) throws IOException {
        byte[] header = new byte[size];
        InputStream input = null;
        try {
            input = file.getInputStream();
            int read = input.read(header);
            if (read < 0) {
                return new byte[0];
            }
            if (read < size) {
                return Arrays.copyOf(header, read);
            }
            return header;
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException ignore) {
                    // ignore close failure while inspecting upload header
                }
            }
        }
    }

    private static String extractExtension(String filename) {
        int index = filename.lastIndexOf('.');
        if (index < 0 || index == filename.length() - 1) {
            return "";
        }
        return filename.substring(index + 1).toLowerCase(Locale.ENGLISH);
    }
}
