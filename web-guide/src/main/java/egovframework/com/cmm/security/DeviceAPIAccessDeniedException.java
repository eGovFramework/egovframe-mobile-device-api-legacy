package egovframework.com.cmm.security;

public class DeviceAPIAccessDeniedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public DeviceAPIAccessDeniedException(String message) {
        super(message);
    }
}
