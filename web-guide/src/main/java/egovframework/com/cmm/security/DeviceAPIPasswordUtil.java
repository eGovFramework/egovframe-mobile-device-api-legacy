package egovframework.com.cmm.security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public final class DeviceAPIPasswordUtil {

    // CVE-2025-22228 완화: BCrypt는 72바이트까지만 쓰고 그 이상은 버리므로,
    // 매우 긴 입력의 해시 연산을 막기 위해 72바이트를 넘으면 거부한다.
    // spring-security-crypto 4.2.x는 Spring 4.3 라인이라 5.x로 올릴 수 없어 길이 제한으로 대응한다.
    private static final int BCRYPT_MAX_PASSWORD_BYTES = 72;

    private static final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder();

    private DeviceAPIPasswordUtil() {
    }

    public static String encode(String plainPassword) {
        if (plainPassword == null) {
            return null;
        }
        if (plainPassword.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > BCRYPT_MAX_PASSWORD_BYTES) {
            throw new IllegalArgumentException("비밀번호가 너무 깁니다.");
        }
        return ENCODER.encode(plainPassword);
    }

    public static boolean matches(String plainPassword, String storedPassword) {
        if (plainPassword == null || storedPassword == null) {
            return false;
        }
        if (plainPassword.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > BCRYPT_MAX_PASSWORD_BYTES) {
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
