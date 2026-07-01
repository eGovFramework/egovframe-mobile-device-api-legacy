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
package egovframework.hyb.ios.cps.service.impl;

import java.util.List;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.ios.cps.service.CompassiOSAPIDefaultVO;
import egovframework.hyb.ios.cps.service.CompassiOSAPIVO;

import org.springframework.stereotype.Repository;


/**  
 * @Class Name : CompassiOSAPIDAO.java
 * @Description :  CompassiOSAPIDAO Class
 * @Modification Information  
 * @
 * @  수정일         수정자                 수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2012.06.18    서형주                  최초생성
 *   2012.08.27    서준식             iOS용 패키지로 변경 
 *   2026.06.26    이백행                  [2026년 컨트리뷰션] 불필요한 예외(throws Exception) 제거
 * @author Device API 실행환경팀
 * @since 2012. 07. 30
 * @version 1.0
 * @see
 * 
 */

@Repository("CompassiOSAPIDAO")
public class CompassiOSAPIDAO extends EgovComAbstractDAO {

	/**
	 * 방향 정보를 등록한다.
	 * @param vo - 등록할 정보가 담긴 CompassiOSAPIVO
	 * @return 등록 결과
	 */
    public int insertCompassInfo(CompassiOSAPIVO vo) {
    	return (Integer)insert("compassiOSAPIDAO.insertCompassInfo", vo);
    }

    /**
	 * 방향 정보를 수정한다.
	 * @param vo - 수정할 정보가 담긴 CompassiOSAPIVO
	 * @return void형
	 */
    public void updateCompassInfo(CompassiOSAPIVO vo) {
        update("compassiOSAPIDAO.updateCompassInfo", vo);
    }

    /**
	 * 방향 정보를 삭제한다.
	 * @param vo - 삭제할 정보가 담긴 CompassiOSAPIVO
	 * @return 등록 결과
	 */
    public int deleteCompassInfo(CompassiOSAPIVO vo) {
    	return (Integer)delete("compassiOSAPIDAO.deleteCompassInfo", vo);
    }

    /**
	 * 방향 정보를 조회한다.
	 * @param vo - 조회할 정보가 담긴 CompassiOSAPIVO
	 * @return 조회한 방향 정보
	 */
    public CompassiOSAPIVO selectCompassInfo(CompassiOSAPIVO vo) {
        return (CompassiOSAPIVO) selectOne("compassiOSAPIDAO.selectCompassInfo", vo);
    }

    /**
	 * 방향 정보 목록을 조회한다.
	 * @param vo - 조회할 정보가 담긴 CompassiOSAPIDefaultVO
	 * @return 방향 정보 목록
	 */
    public List<?> selectCompassInfoList(CompassiOSAPIDefaultVO searchVO) {
        return selectList("compassiOSAPIDAO.selectCompassInfoList", searchVO);
    }

    /**
	 * 방향 정보 총 갯수를 조회한다.
	 * @param  vo - 조회할 정보가 담긴 CompassiOSAPIDefaultVO
	 * @return 방향 정보 총 갯수
	 */
    public int selectCompassInfoListTotCnt(CompassiOSAPIDefaultVO searchVO) {
        return (Integer) selectOne("compassiOSAPIDAO.selectCompassInfoListTotCnt", searchVO);
    }

}
