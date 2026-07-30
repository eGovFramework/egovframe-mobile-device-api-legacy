package egovframework.com.cmm.security;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

import egovframework.rte.fdl.cmmn.exception.EgovBizException;

/**
 * Returns sample-app compatible responses when upload validation fails.
 */
@ControllerAdvice
public class DeviceAPIUploadExceptionHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(DeviceAPIUploadExceptionHandler.class);

    @ExceptionHandler(EgovBizException.class)
    @ResponseBody
    public Object handleUploadValidationFailure(EgovBizException exception, HttpServletRequest request)
            throws EgovBizException {
        String servletPath = request.getServletPath();
        if (!isUploadPath(servletPath)) {
            throw exception;
        }

        LOGGER.warn("Upload rejected on {}: {}", servletPath, exception.getMessage());
        if (servletPath.contains("/frw/")) {
            return "fail";
        }
        return Boolean.FALSE;
    }

    private static boolean isUploadPath(String servletPath) {
        return servletPath.endsWith("/fileUpload.do")
                || servletPath.endsWith("/photoAlbumImageUpload.do")
                || servletPath.endsWith("/photoAlbumImageUploadiOS.do")
                || servletPath.endsWith("/photoAlbumImageUpdate")
                || servletPath.endsWith("/mediaRecordUpload.do")
                || servletPath.endsWith("/mediaiOSRecordUpload.do");
    }
}
