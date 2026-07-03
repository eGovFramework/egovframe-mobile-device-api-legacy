package egovframework.hyb.mbl.bar.service.impl;

import java.util.List;

import javax.annotation.Resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import egovframework.hyb.mbl.bar.service.BarcodescannerAPIDefaultVO;
import egovframework.hyb.mbl.bar.service.BarcodescannerAPIVO;
import egovframework.hyb.mbl.bar.service.EgovBarcodescannerAPIService;
import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;

/**  
 * @Class Name : EgovBarcodescannerAPIService.java
 * @Description : EgovBarcodescannerAPIService Class
 * @Modification Information  
 * @
 * @  수정일       수정자                   수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2016.07.26   신성학                   최초생성
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 07.26
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by Ministry of Interior All right reserved.
 */

@Service("EgovBarcodescannerAPIService")
public class EgovBarcodescannerDeviceAPIServiceimpl extends EgovAbstractServiceImpl implements EgovBarcodescannerAPIService {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(EgovBarcodescannerDeviceAPIServiceimpl.class);
	
	/** PushAPIDAO */
    @Resource(name="BarcodescannerDeviceAPIDAO")
    private BarcodescannerDeviceAPIDAO barcodescannerDeviceAPIDAO;

	/**
	 *barcodescannerDeviceAPI을 위해  정보를 등록한다.
	 * @param vo - 등록할 정보가 담긴 BarcodescannerAPIVO
	 * @return 등록 결과
	 * @exception Exception
	 */
    @Override
    public int insertBarcodescannerDevcie(BarcodescannerAPIVO vo) throws Exception {
    	LOGGER.debug(vo.toString());
    	
    	return barcodescannerDeviceAPIDAO.insertBarcodescannerDevcie(vo);    	
    }

    /**
	 * BarcodescannerDeviceAPI 설정 정보 목록을 조회한다.
	 * @param VO - 조회할 정보가 담긴 VibratorAPIVO
	 * @return 알림 설정 정보 목록
	 * @exception Exception
	 */
    public List<?> selectBarcodescannerList(BarcodescannerAPIDefaultVO searchVO) throws Exception {
        return barcodescannerDeviceAPIDAO.selectBarcodescannerDevcieList(searchVO);
    }

	

}
