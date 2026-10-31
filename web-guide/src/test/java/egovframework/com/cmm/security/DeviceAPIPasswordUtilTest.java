package egovframework.com.cmm.security;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

/**
 * DeviceAPIPasswordUtil 단위 테스트. 서버·DB 없이 동작한다.
 */
public class DeviceAPIPasswordUtilTest {

    @Test
    public void 인코딩한_비밀번호는_매치된다() {
        String encoded = DeviceAPIPasswordUtil.encode("egov1234");
        assertNotNull(encoded);
        assertTrue(DeviceAPIPasswordUtil.matches("egov1234", encoded));
    }

    @Test
    public void 틀린_비밀번호는_매치되지_않는다() {
        String encoded = DeviceAPIPasswordUtil.encode("egov1234");
        assertFalse(DeviceAPIPasswordUtil.matches("wrong-password", encoded));
    }

    @Test
    public void 널은_거짓이다() {
        assertNull(DeviceAPIPasswordUtil.encode(null));
        assertFalse(DeviceAPIPasswordUtil.matches(null, "$2a$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        assertFalse(DeviceAPIPasswordUtil.matches("egov1234", null));
    }

    @Test
    public void bcrypt_해시가_아니면_평문비교한다() {
        assertTrue(DeviceAPIPasswordUtil.matches("1", "1"));
        assertFalse(DeviceAPIPasswordUtil.matches("1", "2"));
    }

    @Test
    public void 일흔두바이트를_넘으면_거부한다() {
        StringBuilder longPassword = new StringBuilder();
        for (int i = 0; i < 73; i++) {
            longPassword.append('a');
        }
        try {
            DeviceAPIPasswordUtil.encode(longPassword.toString());
            fail("73바이트 비밀번호는 거부되어야 한다");
        } catch (IllegalArgumentException e) {
            // 기대함
        }
        String encoded = DeviceAPIPasswordUtil.encode("egov1234");
        assertFalse(DeviceAPIPasswordUtil.matches(longPassword.toString(), encoded));
    }

    @Test
    public void 일흔두바이트는_허용한다() {
        StringBuilder password = new StringBuilder();
        for (int i = 0; i < 72; i++) {
            password.append('a');
        }
        String encoded = DeviceAPIPasswordUtil.encode(password.toString());
        assertTrue(DeviceAPIPasswordUtil.matches(password.toString(), encoded));
    }
}
