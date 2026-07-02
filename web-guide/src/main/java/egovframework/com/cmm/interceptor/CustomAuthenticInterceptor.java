package egovframework.com.cmm.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import egovframework.com.cmm.security.DeviceAPIAccessDeniedException;
import egovframework.com.cmm.security.DeviceAPIAuthSupport;

/**
 * 인증여부 체크 인터셉터
 * @author 공통서비스 개발팀 서준식
 * @since 2011.07.01
 * @version 1.0
 * @see
 *
 * <pre>
 * << 개정이력(Modification Information) >>
 *
 *   수정일      수정자          수정내용
 *  -------    --------    ---------------------------
 *  2011.07.01  서준식          최초 생성
 *  2011.09.07  서준식          인증이 필요없는 URL을 패스하는 로직 추가
 *  </pre>
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
