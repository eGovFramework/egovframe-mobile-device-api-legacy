package kr.go.egovframework.hyb.plugin;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

import org.json.JSONException;

import android.content.Context;

/**
 * Validates EgovFileOpener download requests before files are written locally.
 */
public final class EgovFileOpenerRequestValidator {

    public static final String ERROR_SECURE_URL = "HTTPS server URL is required";
    public static final String ERROR_URI = "Download URI is not allowed";
    public static final String ERROR_FILENAME = "File name is invalid";
    public static final String ERROR_TARGET_PATH = "Target path is not allowed";

    private static final int MAX_URI_LENGTH = 256;
    private static final int MAX_FILENAME_LENGTH = 255;
    private static final String FOP_PREFIX = "/fop/";

    private static final Pattern URI_PATH_PATTERN =
            Pattern.compile("^/[a-zA-Z0-9][a-zA-Z0-9_./-]*$");
    private static final Pattern URI_QUERY_PATTERN =
            Pattern.compile("^[a-zA-Z0-9_./=&%-]*$");
    private static final Pattern STORED_FILENAME_PATTERN =
            Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9._-]*$");

    private static final Set<String> ALLOWED_EXTENSIONS = new HashSet<String>(Arrays.asList(
            "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip",
            "jpg", "jpeg", "png", "gif", "bmp", "mp3", "mp4", "m4a", "wav", "3gp", "hwp"));

    private static final Set<String> DANGEROUS_EXTENSIONS = new HashSet<String>(Arrays.asList(
            "html", "htm", "js", "jsx", "mjs", "jsp", "php", "asp", "aspx",
            "sh", "bash", "bat", "cmd", "exe", "apk", "dex", "so", "dylib", "xml", "plist"));

    private EgovFileOpenerRequestValidator() {
    }

    public static String normalizeDownloadUri(String rawUri) throws JSONException {
        if (rawUri == null || rawUri.trim().isEmpty()) {
            throw new JSONException(ERROR_URI);
        }

        String trimmed = rawUri.trim();
        String path = trimmed;
        String query = null;

        int queryIndex = trimmed.indexOf('?');
        if (queryIndex >= 0) {
            path = trimmed.substring(0, queryIndex);
            query = trimmed.substring(queryIndex + 1);
        }
        int fragmentIndex = path.indexOf('#');
        if (fragmentIndex >= 0) {
            path = path.substring(0, fragmentIndex);
        }

        if (path.length() > MAX_URI_LENGTH
                || path.contains("..")
                || path.contains("\\")
                || path.contains("%")
                || !path.startsWith("/")
                || !URI_PATH_PATTERN.matcher(path).matches()
                || !path.startsWith(FOP_PREFIX)) {
            throw new JSONException(ERROR_URI);
        }

        if (query != null) {
            if (query.length() > MAX_URI_LENGTH || !URI_QUERY_PATTERN.matcher(query).matches()) {
                throw new JSONException(ERROR_URI);
            }
            return path + "?" + query;
        }
        return path;
    }

    public static String buildDownloadUrl(Context context, String serverUrl, String rawUri)
            throws JSONException {
        if (!EgovInterfaceRequestValidator.isSecureServerUrl(context, serverUrl)) {
            throw new JSONException(ERROR_SECURE_URL);
        }
        return serverUrl + normalizeDownloadUri(rawUri);
    }

    public static String normalizeFileName(String rawFileName) throws JSONException {
        if (rawFileName == null || rawFileName.trim().isEmpty()) {
            throw new JSONException(ERROR_FILENAME);
        }

        String fileName = rawFileName.trim().replace('\\', '/');
        int slashIndex = fileName.lastIndexOf('/');
        if (slashIndex >= 0) {
            fileName = fileName.substring(slashIndex + 1);
        }

        if (fileName.isEmpty()
                || fileName.length() > MAX_FILENAME_LENGTH
                || fileName.contains("..")
                || fileName.indexOf('/') >= 0
                || fileName.indexOf('\\') >= 0
                || fileName.indexOf('\0') >= 0) {
            throw new JSONException(ERROR_FILENAME);
        }

        String extension = extractExtension(fileName);
        if (extension.isEmpty()
                || DANGEROUS_EXTENSIONS.contains(extension)
                || !ALLOWED_EXTENSIONS.contains(extension)) {
            throw new JSONException(ERROR_FILENAME);
        }
        return fileName;
    }

    public static String normalizeStoredFileName(String rawStoredFileName) throws JSONException {
        if (rawStoredFileName == null || rawStoredFileName.trim().isEmpty()) {
            return "";
        }

        String storedFileName = rawStoredFileName.trim();
        if (storedFileName.length() > MAX_FILENAME_LENGTH
                || storedFileName.contains("..")
                || storedFileName.contains("/")
                || storedFileName.contains("\\")
                || storedFileName.indexOf('\0') >= 0
                || !STORED_FILENAME_PATTERN.matcher(storedFileName).matches()) {
            throw new JSONException(ERROR_FILENAME);
        }
        return storedFileName;
    }

    public static File resolveSecureTargetFile(Context context, String rawTargetPath, String fileName)
            throws JSONException, IOException {
        File targetDirectory = resolveSecureTargetDirectory(context, rawTargetPath);
        File targetFile = new File(targetDirectory, fileName).getCanonicalFile();
        String targetDirectoryPath = targetDirectory.getCanonicalPath();
        String targetFilePath = targetFile.getPath();
        if (!targetFilePath.equals(targetDirectoryPath)
                && !targetFilePath.startsWith(targetDirectoryPath + File.separator)) {
            throw new IOException(ERROR_TARGET_PATH);
        }
        return targetFile;
    }

    public static File resolveSecureTargetDirectory(Context context, String rawTargetPath)
            throws IOException {
        String normalizedPath = normalizePathPrefix(rawTargetPath);
        if (normalizedPath == null || normalizedPath.isEmpty()) {
            normalizedPath = new File(context.getFilesDir(), "www").getPath();
        }

        File targetDirectory = new File(normalizedPath).getCanonicalFile();
        if (!isUnderAllowedAppDirectory(context, targetDirectory)) {
            throw new IOException(ERROR_TARGET_PATH);
        }
        if (!targetDirectory.exists() && !targetDirectory.mkdirs()) {
            throw new IOException("Failed to create target directory");
        }
        if (!targetDirectory.isDirectory()) {
            throw new IOException(ERROR_TARGET_PATH);
        }
        return targetDirectory;
    }

    private static String normalizePathPrefix(String rawTargetPath) {
        if (rawTargetPath == null) {
            return null;
        }
        String normalized = rawTargetPath.trim();
        if (normalized.isEmpty() || "null".equalsIgnoreCase(normalized)) {
            return null;
        }
        if (normalized.startsWith("file://")) {
            normalized = normalized.substring("file://".length());
        }
        return normalized;
    }

    private static boolean isUnderAllowedAppDirectory(Context context, File canonicalDirectory)
            throws IOException {
        String directoryPath = canonicalDirectory.getPath();
        File[] allowedRoots = getAllowedRootDirectories(context);
        for (File root : allowedRoots) {
            if (root == null) {
                continue;
            }
            String rootPath = root.getCanonicalFile().getPath();
            if (directoryPath.equals(rootPath)
                    || directoryPath.startsWith(rootPath + File.separator)) {
                return true;
            }
        }
        return false;
    }

    private static File[] getAllowedRootDirectories(Context context) throws IOException {
        File externalFilesDir = context.getExternalFilesDir(null);
        File externalCacheDir = context.getExternalCacheDir();
        return new File[] {
                context.getFilesDir(),
                context.getCacheDir(),
                externalFilesDir,
                externalCacheDir
        };
    }

    private static String extractExtension(String fileName) {
        int index = fileName.lastIndexOf('.');
        if (index < 0 || index == fileName.length() - 1) {
            return "";
        }
        return fileName.substring(index + 1).toLowerCase(Locale.ENGLISH);
    }
}
