package egovframework.com.cmm.security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public final class DeviceAPIPasswordUtil {

    private static final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder();

    private DeviceAPIPasswordUtil() {
    }

    public static String encode(String plainPassword) {
        if (plainPassword == null) {
            return null;
        }
        return ENCODER.encode(plainPassword);
    }

    public static boolean matches(String plainPassword, String storedPassword) {
        if (plainPassword == null || storedPassword == null) {
            return false;
        }
        if (isBcryptHash(storedPassword)) {
            return ENCODER.matches(plainPassword, storedPassword);
        }
        return storedPassword.equals(plainPassword);
    }

    public static boolean isBcryptHash(String storedPassword) {
        return storedPassword != null
                && (storedPassword.startsWith("$2a$") || storedPassword.startsWith("$2b$"));
    }
}
