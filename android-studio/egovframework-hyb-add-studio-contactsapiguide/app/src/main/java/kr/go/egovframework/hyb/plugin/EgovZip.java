package kr.go.egovframework.hyb.plugin;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.StringTokenizer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.content.Context;
import android.net.Uri;
import android.util.Log;

public class EgovZip extends CordovaPlugin {

    private static final int COMPRESSION_LEVEL = 8;
    private static final int BUFFER_SIZE = 1024 * 2;
    private static final long MAX_TOTAL_UNCOMPRESSED_SIZE = 100L * 1024L * 1024L;
    private static final int MAX_COMPRESSION_RATIO = 100;

    @Override
    public boolean execute(String action, JSONArray data, CallbackContext callbackContext) throws JSONException {

        Log.d(this.getClass().getSimpleName(), ">>>>> action = " + action);
        if ("unzip".equals(action)) {

            String zipFile = Uri.parse(data.getString(0)).getPath();
            String targetDir = Uri.parse(data.getString(1)).getPath();

            Log.d(this.getClass().getSimpleName(), ">>>>> zipFile = " + zipFile);
            Log.d(this.getClass().getSimpleName(), ">>>>> targetDir = " + targetDir);

            if (!validateDestinationPath(cordova.getContext(), targetDir)) {
                callbackContext.error("Destination path outside app files directory");
                return true;
            }

            unzip(zipFile, targetDir, callbackContext);

            return true;
        } else if ("zip".equals(action)) {

            String zipFile = Uri.parse(data.getString(0)).getPath();
            String targetDir = Uri.parse(data.getString(1)).getPath();

            Log.d(this.getClass().getSimpleName(), ">>>>> zipFile = " + zipFile);
            Log.d(this.getClass().getSimpleName(), ">>>>> targetDir = " + targetDir);

            zip(zipFile, targetDir, callbackContext);

            return true;
        }
        return false;
    }

    private void unzip(String zipFile, String targetDir, CallbackContext callbackContext) {

        try {
            unzip(zipFile, targetDir, false);
        } catch (Exception e) {
            e.printStackTrace();
        }
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, new JSONObject()));

    }

    private void zip(String zipFile, String targetDir, CallbackContext callbackContext) {

        try {
            zip(zipFile, targetDir);
        } catch (Exception e) {
            e.printStackTrace();
        }
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, new JSONObject()));

    }

    /**
     * 지정된 폴더를 Zip 파일로 압축한다.
     */
    public static void zip(String sourcePath, String output) throws Exception {

        File sourceFile = new File(sourcePath);
        if (!sourceFile.isFile() && !sourceFile.isDirectory()) {
            throw new Exception("압축 대상의 파일을 찾을 수가 없습니다.");
        }

        FileOutputStream fos = null;
        BufferedOutputStream bos = null;
        ZipOutputStream zos = null;

        try {
            fos = new FileOutputStream(output);
            bos = new BufferedOutputStream(fos);
            zos = new ZipOutputStream(bos);
            zos.setLevel(COMPRESSION_LEVEL);

            zipEntry(sourceFile, sourcePath, zos);
            zos.finish();
        } finally {
            if (zos != null) {
                zos.close();
            }
            if (bos != null) {
                bos.close();
            }
            if (fos != null) {
                fos.close();
            }
        }
    }

    private static void zipEntry(File sourceFile, String sourcePath, ZipOutputStream zos) throws Exception {
        if (sourceFile.isDirectory()) {
            Log.d("dir >>>", "dir = " + sourceFile.getPath());
            if (sourceFile.getName().equalsIgnoreCase(".metadata")) {
                return;
            }
            File[] fileArray = sourceFile.listFiles();
            for (int i = 0; i < fileArray.length; i++) {
                zipEntry(fileArray[i], sourcePath, zos);
            }
        } else {
            BufferedInputStream bis = null;

            try {
                String sFilePath = sourceFile.getPath();
                Log.i("file >>>", sFilePath);
                StringTokenizer tok = new StringTokenizer(sFilePath, "/");

                int tok_len = tok.countTokens();
                String zipEntryName = tok.toString();
                while (tok_len != 0) {
                    tok_len--;
                    zipEntryName = tok.nextToken();
                }
                bis = new BufferedInputStream(new FileInputStream(sourceFile));

                ZipEntry zentry = new ZipEntry(zipEntryName);
                zentry.setTime(sourceFile.lastModified());
                zos.putNextEntry(zentry);

                byte[] buffer = new byte[BUFFER_SIZE];
                int cnt = 0;

                while ((cnt = bis.read(buffer, 0, BUFFER_SIZE)) != -1) {
                    zos.write(buffer, 0, cnt);
                }
                zos.closeEntry();
            } finally {
                if (bis != null) {
                    bis.close();
                }
            }
        }
    }

    /**
     * Zip 파일의 압축을 푼다.
     */
    public static void unzip(String zipFile, String targetDir, boolean fileNameToLowerCase) throws Exception {
        unzip(zipFile, targetDir, fileNameToLowerCase, null);
    }

    public static void unzip(String zipFile, String targetDir, boolean fileNameToLowerCase, Context context) throws Exception {
        if (context != null && !validateDestinationPath(context, targetDir)) {
            throw new SecurityException("Destination path outside app files directory: " + targetDir);
        }
        FileInputStream fis = null;
        ZipInputStream zis = null;
        ZipEntry zentry = null;
        long totalUncompressedSize = 0L;

        try {
            File targetDirectory = new File(targetDir);
            if (!targetDirectory.exists() && !targetDirectory.mkdirs()) {
                throw new IOException("Failed to create target directory: " + targetDir);
            }

            fis = new FileInputStream(zipFile);
            zis = new ZipInputStream(fis);

            while ((zentry = zis.getNextEntry()) != null) {
                String fileNameToUnzip = zentry.getName();
                if (fileNameToLowerCase) {
                    fileNameToUnzip = fileNameToUnzip.toLowerCase();
                }

                validateZipEntryName(fileNameToUnzip);
                validateCompressionRatio(zentry);

                File targetFile = resolveSecureTargetFile(targetDirectory, fileNameToUnzip);

                if (zentry.isDirectory()) {
                    if (!targetFile.mkdirs() && !targetFile.isDirectory()) {
                        throw new IOException("Failed to create directory: " + targetFile.getAbsolutePath());
                    }
                } else {
                    File parent = targetFile.getParentFile();
                    if (parent != null && !parent.exists() && !parent.mkdirs()) {
                        throw new IOException("Failed to create parent directory: " + parent.getAbsolutePath());
                    }
                    long written = unzipEntry(zis, targetFile);
                    totalUncompressedSize += written;
                    if (totalUncompressedSize > MAX_TOTAL_UNCOMPRESSED_SIZE) {
                        throw new SecurityException("ZIP uncompressed size exceeds allowed limit");
                    }
                }
            }
        } finally {
            if (zis != null) {
                zis.close();
            }
            if (fis != null) {
                fis.close();
            }
        }
    }

    private static void validateZipEntryName(String entryName) throws SecurityException {
        if (entryName == null || entryName.trim().isEmpty()) {
            throw new SecurityException("Empty ZIP entry name");
        }
        if (entryName.startsWith("/") || entryName.startsWith("\\")) {
            throw new SecurityException("Absolute path in ZIP entry: " + entryName);
        }
        if (entryName.length() >= 2 && entryName.charAt(1) == ':') {
            throw new SecurityException("Drive letter in ZIP entry: " + entryName);
        }

        String normalized = entryName.replace('\\', '/');
        String[] parts = normalized.split("/");
        for (String part : parts) {
            if ("..".equals(part)) {
                throw new SecurityException("Path traversal in ZIP entry: " + entryName);
            }
        }
    }

    private static void validateCompressionRatio(ZipEntry zentry) throws SecurityException {
        long compressedSize = zentry.getCompressedSize();
        long uncompressedSize = zentry.getSize();
        if (compressedSize > 0 && uncompressedSize > 0) {
            long ratio = uncompressedSize / compressedSize;
            if (ratio > MAX_COMPRESSION_RATIO) {
                throw new SecurityException("ZIP entry compression ratio exceeds allowed limit");
            }
        }
    }

    private static File resolveSecureTargetFile(File targetDir, String entryName) throws IOException {
        File targetDirCanonical = targetDir.getCanonicalFile();
        File targetFile = new File(targetDirCanonical, entryName);
        File targetFileCanonical = targetFile.getCanonicalFile();
        String targetDirPath = targetDirCanonical.getPath();
        String targetFilePath = targetFileCanonical.getPath();
        if (!targetFilePath.equals(targetDirPath)
                && !targetFilePath.startsWith(targetDirPath + File.separator)) {
            throw new SecurityException("ZIP entry outside target directory: " + entryName);
        }
        return targetFile;
    }

    protected static long unzipEntry(ZipInputStream zis, File targetFile) throws Exception {
        FileOutputStream fos = null;
        long totalWritten = 0L;
        try {
            fos = new FileOutputStream(targetFile);

            byte[] buffer = new byte[BUFFER_SIZE];
            int len = 0;
            while ((len = zis.read(buffer)) != -1) {
                totalWritten += len;
                if (totalWritten > MAX_TOTAL_UNCOMPRESSED_SIZE) {
                    throw new SecurityException("ZIP entry size exceeds allowed limit");
                }
                fos.write(buffer, 0, len);
            }
        } finally {
            if (fos != null) {
                fos.close();
            }
        }
        return totalWritten;
    }

    public static boolean validateDestinationPath(Context context, String destinationPath) {
        if (context == null || destinationPath == null || destinationPath.trim().isEmpty()) {
            return false;
        }
        try {
            File canonicalTarget = new File(destinationPath).getCanonicalFile();
            File filesDir = context.getFilesDir().getCanonicalFile();
            String canonicalPath = canonicalTarget.getPath();
            String filesDirPath = filesDir.getPath();
            return canonicalPath.equals(filesDirPath)
                    || canonicalPath.startsWith(filesDirPath + File.separator);
        } catch (IOException e) {
            return false;
        }
    }

}
