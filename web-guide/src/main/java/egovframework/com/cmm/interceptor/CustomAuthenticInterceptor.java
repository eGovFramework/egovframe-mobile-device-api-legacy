package egovframework.com.cmm.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import egovframework.com.cmm.security.DeviceAPIAccessDeniedException;
import egovframework.com.cmm.security.DeviceAPIAuthSupport;

/**
 * Device API uuid ownership interceptor.
 */
public class CustomAuthenticInterceptor extends HandlerInterceptorAdapter {

    private final Logger log = LoggerFactory.getLogger(CustomAuthenticInterceptor.class);

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String servletPath = request.getServletPath();

        if (DeviceAPIAuthSupport.isPublicPath(servletPath)) {
            String uuid = DeviceAPIAuthSupport.getRequestUuid(request);
            if (uuid != null) {
                DeviceAPIAuthSupport.bindDeviceUuid(request, uuid);
            }
            return true;
        }

        try {
            DeviceAPIAuthSupport.ensureDeviceAccess(request);
            return true;
        } catch (DeviceAPIAccessDeniedException e) {
            log.warn("Device API access denied: {} {}", servletPath, e.getMessage());
            response.sendError(HttpServletResponse.SC_FORBIDDEN, e.getMessage());
            return false;
        }
    }
}
