package egovframework.hyb.mbl.jai.service;

import java.util.List;

/**  
 * @Class Name : EgovJailbreakDetectionDeviceAPIService
 * @Description : EgovJailbreakDetectionDeviceAPIService interface
 * @Modification Information  
 * @
 * @  수정일       수정자                  수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2016.07.26    신성학                최초 작성
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 07. 26
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by Ministry of Interior All right reserved.
 */

public interface EgovJailbreakDetectionDeviceAPIService {
	/**
	 * JailbreakDetection을 위해JailbreakDetection 정보를 등록한다.
	 * @param vo - 등록할 정보가 담긴 BarcodescannerAPIVO
	 * @return 등록 결과
	 * @exception Exception
	 */
    int insertJailbreakDetectionDevcie(JailbreakDetectionDeviceAPIVO vo) throws Exception;
    
	/**
	 * JailbreakDetection을 위해 JailbreakDetection 정보를 서버에서 조회한다.
	 * @param vo - 등록할 정보가 담긴 BarcodescannerAPIVO
	 * @return 등록 결과
	 * @exception Exception
	 */
	List<?> selectJailbreakDetectionDevcieList(JailbreakDetectionDeviceAPIDefaultVO searchVO) throws Exception;

}
