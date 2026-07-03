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
package egovframework.hyb.ios.gps.service.impl;

import java.util.List;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.ios.gps.service.GPSiOSAPIDefaultVO;
import egovframework.hyb.ios.gps.service.GPSiOSAPIVO;

import org.springframework.stereotype.Repository;


/**  
 * @Class Name : GPSAPIDAO.java
 * @Description : GPSAPI DAO Class
 * @Modification Information  
 * @
 * @  수정일              수정자                 수정내용
 * @ 
 * @ 2012.07.31   이한철                 최초생성
 *   2026.06.26   이백행                 [2026년 컨트리뷰션] 불필요한 예외(throws Exception) 제거
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 05. 14
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

@Repository("GPSAPIDAO")
public class GPSiOSAPIDAO extends EgovComAbstractDAO {

    /**
     * gps 정보를 등록한다.
     * 
     * @param vo
     *            - 등록할 정보가 담긴 GPSAPIVO
     * @return 등록 결과
     */
    public void insertGPSInfo(GPSiOSAPIVO vo) {
        insert("gpsiOSAPIDAO.insertGPSInfo", vo);
    }

    /**
     * gps 정보를 삭제한다.
     * 
     * @param vo
     *            - 삭제할 정보가 담긴 GPSAPIVO
     * @return void형
     */
    public void deleteGPSInfo(GPSiOSAPIVO vo) {
        delete("gpsiOSAPIDAO.deleteGPSInfo", vo);
    }

    /**
     * gps 정보 목록을 조회한다.
     * 
     * @param vo
     *            - 조회할 정보가 담긴 GPSAPIDefaultVO
     * @return gps 정보 목록
     */
    public List<?> selectGPSInfoList(GPSiOSAPIDefaultVO searchVO) {
        return selectList("gpsiOSAPIDAO.selectGPSInfoList", searchVO);
    }

    /**
     * gps 정보 총 갯수를 조회한다.
     * 
     * @param vo
     *            - 조회할 정보가 담긴 GPSAPIDefaultVO
     * @return 네트워크 정보 총 갯수
     */
    public int selectGPSInfoListTotCnt(GPSiOSAPIDefaultVO searchVO) {
        return (Integer) selectOne(
                "gpsiOSAPIDAO.selectGPSInfoListTotCnt", searchVO);
    }

}
