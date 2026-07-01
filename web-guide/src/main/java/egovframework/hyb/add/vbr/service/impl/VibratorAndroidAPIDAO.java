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
package egovframework.hyb.add.vbr.service.impl;

import java.util.List;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.add.vbr.service.VibratorAndroidAPIDefaultVO;
import egovframework.hyb.add.vbr.service.VibratorAndroidAPIVO;

import org.springframework.stereotype.Repository;

/**  
 * @Class Name : VibratorAndroidAPIDAO.java
 * @Description : VibratorAndroidAPIDAO Class
 * @Modification Information  
 * @
 * @  수정일            수정자        수정내용
 * @ ---------        ---------    -------------------------------
 * @ 2012. 8. 16.        이율경        최초생성
 * @ 2026. 6. 26.        이백행        [2026년 컨트리뷰션] 불필요한 예외(throws Exception) 제거
 * 
 * @author 디바이스 API 실행환경 팀
 * @since 2012. 8. 16.
 * @version 1.0
 * @see
 * 
 */
@Repository("VibratorAndroidAPIDAO")
public class VibratorAndroidAPIDAO extends EgovComAbstractDAO {

    /**
     * 알람 정보를 등록한다.
     * @param vo - 등록할 정보가 담긴 VibratorAPIVO
     * @return 등록 결과
     */
    public int insertVibrator(VibratorAndroidAPIVO vo) {
        return (Integer)insert("vibratorAndroidAPIDAO.insertVibrator", vo);
    }

    /**
     * 알람 정보 목록을 조회한다.
     * @param vo - 조회할 정보가 담긴 VibratorAPIDefaultVO
     * @return 네트워크 정보 목록
     */
    public List<?> selectVibratorList(VibratorAndroidAPIDefaultVO searchVO) {
        return selectList("vibratorAndroidAPIDAO.selectVibratorList", searchVO);
    }
}
