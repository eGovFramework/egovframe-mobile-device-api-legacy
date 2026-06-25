/*
 * Copyright 2008-2009 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package egovframework.hyb.ios.vbr.service.impl;

import java.util.List;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.ios.vbr.service.VibratoriOSAPIDefaultVO;
import egovframework.hyb.ios.vbr.service.VibratoriOSAPIVO;

import org.springframework.stereotype.Repository;


/**  
 * @Class Name : VibratoriOSAPIDAO.java
 * @Description : VibratoriOSAPI DAO Class
 * @Modification Information  
 * @
 * @  수정일      수정자                 수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2012.07.18   이해성                최초생성
 *   2026.06.26   이백행                [2026년 컨트리뷰션] 불필요한 예외(throws Exception) 제거
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 07. 18
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

@Repository("VibratoriOSAPIDAO")
public class VibratoriOSAPIDAO extends EgovComAbstractDAO {

	/**
	 * 알람 정보를 등록한다.
	 * @param vo - 등록할 정보가 담긴 VibratorAPIVO
	 * @return 등록 결과
	 */
    public int insertVibrator(VibratoriOSAPIVO vo) {
        return (Integer)insert("vibratoriOSAPIDAO.insertVibrator", vo);
    }

    /**
	 * 알람 정보 목록을 조회한다.
	 * @param vo - 조회할 정보가 담긴 VibratorAPIDefaultVO
	 * @return 네트워크 정보 목록
	 */
    public List<?> selectVibratorList(VibratoriOSAPIDefaultVO searchVO) {
        return selectList("vibratoriOSAPIDAO.selectVibratorList", searchVO);
    }
}
