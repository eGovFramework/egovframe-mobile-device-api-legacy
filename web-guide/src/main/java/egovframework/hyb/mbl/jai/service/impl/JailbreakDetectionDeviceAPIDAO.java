package egovframework.hyb.mbl.jai.service.impl;

import java.util.List;

import org.springframework.stereotype.Repository;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.mbl.jai.service.JailbreakDetectionDeviceAPIDefaultVO;
import egovframework.hyb.mbl.jai.service.JailbreakDetectionDeviceAPIVO;

/**  
 * @Class Name : JailbreakDetectionDeviceAPIDAO
 * @Description : JailbreakDetectionDeviceAPIDAO Class
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

@Repository("JailbreakDetectionDeviceAPIDAO")
public class JailbreakDetectionDeviceAPIDAO extends EgovComAbstractDAO{
	
	/**
	 * JailbreakDetectionDevice 정보를 등록한다.
	 * @param vo - 등록할 정보가 담긴 JailbreakDetectionAPIVO
	 * @return 등록 결과
	 * @exception Exception
	 */
    public int insertJailbreakDetectionDevcie(JailbreakDetectionDeviceAPIVO vo) throws Exception {
    	
        return (Integer)insert("jailbreakDetectionDeviceAPIDAO.insertJailbreakDetectionDevcie", vo);
        
    }

    

	/**
	 * JailbreakDetectionDevice 정보를 조회한다.
	 * @param vo - 등록할 정보가 담긴 JailbreakDetectionAPIVO
	 * @return 등록 결과
	 * @exception Exception
	 */
	public List<?> selectJailbreakDetectionDevcieList(JailbreakDetectionDeviceAPIDefaultVO searchVO) throws Exception{

		return selectList("jailbreakDetectionDeviceAPIDAO.selectJailbreakDetectionDevcieList", searchVO);
	}

}
