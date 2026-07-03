package egovframework.hyb.mbl.jai.service.impl;

import java.util.List;

import javax.annotation.Resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import egovframework.hyb.mbl.jai.service.EgovJailbreakDetectionDeviceAPIService;
import egovframework.hyb.mbl.jai.service.JailbreakDetectionDeviceAPIDefaultVO;
import egovframework.hyb.mbl.jai.service.JailbreakDetectionDeviceAPIVO;
import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;

/**  
 * @Class Name : EgovJailbreakDetectionDeviceAPIServiceImpl
 * @Description : EgovJailbreakDetectionDeviceAPIServiceImpl Class
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

@Service ("EgovJailbreakDetectionDeviceAPIService")
public class EgovJailbreakDetectionDeviceAPIServiceImpl extends EgovAbstractServiceImpl implements EgovJailbreakDetectionDeviceAPIService {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(EgovJailbreakDetectionDeviceAPIServiceImpl.class);
	
	/** JailbreakDetectionAPIDAO */
    @Resource(name="JailbreakDetectionDeviceAPIDAO")
    private JailbreakDetectionDeviceAPIDAO jailbreakdetectionDeviceAPIDAO;
    
	/**
	 *JailbreakDetectionDeviceAPI을 위해  정보를 등록한다.
	 * @param vo - 등록할 정보가 담긴 JailbreakDetectionAPIVO
	 * @return 등록 결과
	 * @exception Exception
	 */
    @Override
    public int insertJailbreakDetectionDevcie(JailbreakDetectionDeviceAPIVO vo) throws Exception {
    	LOGGER.debug(vo.toString());
    	
    	return jailbreakdetectionDeviceAPIDAO.insertJailbreakDetectionDevcie(vo);    	
    }

    /**
	 * JailbreakDetectionDeviceAPI 설정 정보 목록을 조회한다.
	 * @param VO - 조회할 정보가 담긴 JailbreakDetectionAPIVO
	 * @return 알림 설정 정보 목록
	 * @exception Exception
	 */
    public List<?> selectJailbreakDetectionDevcieList(JailbreakDetectionDeviceAPIDefaultVO searchVO) throws Exception {
        return jailbreakdetectionDeviceAPIDAO.selectJailbreakDetectionDevcieList(searchVO);
    }

}
