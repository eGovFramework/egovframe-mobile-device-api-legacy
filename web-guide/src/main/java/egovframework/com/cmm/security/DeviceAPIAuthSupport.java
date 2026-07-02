package egovframework.com.cmm.security;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public final class DeviceAPIAuthSupport {

    public static final String LOGIN_SESSION_KEY = "DEVICE_API_LOGIN";
    public static final String DEVICE_UUID_SESSION_KEY = "DEVICE_API_BOUND_UUID";

    private static final String[] PUBLIC_PATH_SUFFIXES = {
            "/itf/logIn.do",
            "/itf/xml/logIn.do",
            "/itf/logIniOS.do",
            "/itf/addInterfaceInfo.do",
            "/itf/xml/addInterfaceInfo.do",
            "/itf/addInterfaceiOSInfo.do",
            "/dvc/xml/addDeviceInfo.do",
            "/upd/ResourceUpdateVersionInfo.do",
            "/upd/ResourceUpdatefileDownload.do"
    };

    private DeviceAPIAuthSupport() {
    }

    public static boolean isPublicPath(String servletPath) {
        if (servletPath == null) {
            return false;
        }
        for (String suffix : PUBLIC_PATH_SUFFIXES) {
            if (servletPath.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    public static DeviceAPILoginVO getLogin(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        Object value = session.getAttribute(LOGIN_SESSION_KEY);
        if (value instanceof DeviceAPILoginVO) {
            return (DeviceAPILoginVO) value;
        }
        return null;
    }

    public static void bindLogin(HttpServletRequest request, DeviceAPILoginVO loginVO) {
        HttpSession session = request.getSession(true);
        session.setAttribute(LOGIN_SESSION_KEY, loginVO);
        if (loginVO != null && loginVO.getUuid() != null && !loginVO.getUuid().trim().isEmpty()) {
            bindDeviceUuid(request, loginVO.getUuid());
        }
    }

    public static void bindDeviceUuid(HttpServletRequest request, String uuid) {
        if (uuid == null || uuid.trim().isEmpty()) {
            return;
        }
        HttpSession session = request.getSession(true);
        session.setAttribute(DEVICE_UUID_SESSION_KEY, uuid.trim());
    }

    public static String getBoundDeviceUuid(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        Object value = session.getAttribute(DEVICE_UUID_SESSION_KEY);
        return value == null ? null : value.toString();
    }

    public static String getRequestUuid(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String uuid = request.getParameter("uuid");
        if (uuid == null || uuid.trim().isEmpty()) {
            return null;
        }
        return uuid.trim();
    }

    /**
     * Ensures the current HTTP session is bound to a single device uuid.
     * Local samples send uuid on the first API call; the first value is bound to the session.
     */
    public static void ensureDeviceAccess(HttpServletRequest request) {
        String requestUuid = getRequestUuid(request);
        String boundUuid = getBoundDeviceUuid(request);

        if (boundUuid == null) {
            if (requestUuid != null) {
                bindDeviceUuid(request, requestUuid);
                boundUuid = requestUuid;
            } else {
                throw new DeviceAPIAccessDeniedException("Device session is not established.");
            }
        } else if (requestUuid != null && !boundUuid.equals(requestUuid)) {
            throw new DeviceAPIAccessDeniedException("Device ownership validation failed.");
        }

        DeviceAPILoginVO loginVO = getLogin(request);
        if (loginVO != null && loginVO.getUuid() != null && !loginVO.getUuid().equals(boundUuid)) {
            throw new DeviceAPIAccessDeniedException("Login device mismatch.");
        }
    }

    public static String requireBoundDeviceUuid(HttpServletRequest request) {
        ensureDeviceAccess(request);
        String boundUuid = getBoundDeviceUuid(request);
        if (boundUuid == null || boundUuid.isEmpty()) {
            throw new DeviceAPIAccessDeniedException("Device uuid is required.");
        }
        return boundUuid;
    }

    public static String resolveDeviceUuid(HttpServletRequest request, String requestUuid) {
        ensureDeviceAccess(request);
        if (requestUuid != null && !requestUuid.trim().isEmpty()) {
            String trimmed = requestUuid.trim();
            String boundUuid = getBoundDeviceUuid(request);
            if (boundUuid != null && !boundUuid.equals(trimmed)) {
                throw new DeviceAPIAccessDeniedException("Device ownership validation failed.");
            }
            return trimmed;
        }
        return requireBoundDeviceUuid(request);
    }

    public static void assertOwnedUuid(HttpServletRequest request, String ownerUuid) {
        String boundUuid = requireBoundDeviceUuid(request);
        if (ownerUuid == null || !boundUuid.equals(ownerUuid)) {
            throw new DeviceAPIAccessDeniedException("Resource ownership validation failed.");
        }
    }
}
