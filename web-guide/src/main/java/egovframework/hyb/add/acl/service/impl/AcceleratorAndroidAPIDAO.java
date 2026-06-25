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
package egovframework.hyb.add.acl.service.impl;

import java.util.List;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.add.acl.service.AcceleratorAndroidAPIDefaultVO;
import egovframework.hyb.add.acl.service.AcceleratorAndroidAPIVO;

import org.springframework.stereotype.Repository;


/**  
 * @Class Name : AcceleratorAPIDAO.java
 * @Description : AcceleratorAPI DAO Class
 * @Modification Information  
 * @
 * @  수정일                 수정자                 수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2012.06.18    서형주                  최초생성
 * @ 2026.06.26    이백행                  [2026년 컨트리뷰션] 불필요한 예외(throws Exception) 제거
 * 
 * @author Device API 실행환경팀
 * @since 2012. 07. 23
 * @version 1.0
 * @see
 * 
 */

@Repository("AcceleratorAndroidAPIDAO")
public class AcceleratorAndroidAPIDAO extends EgovComAbstractDAO {

    /**
     * 가속도 정보를 등록한다.
     * @param vo - 등록할 정보가 담긴 AcceleratorAPIVO
     * @return 등록 결과
     */
    public int insertAcceleratorInfo(AcceleratorAndroidAPIVO vo) {
        return (Integer)insert("acceleratorAndroidAPIDAO.insertAcceleratorInfo", vo);
    }

    /**
     * 가속도 정보를 수정한다.
     * @param vo - 수정할 정보가 담긴 AcceleratorAPIVO
     * @return void형
     */
    public void updateAcceleratorInfo(AcceleratorAndroidAPIVO vo) {
        update("acceleratorAndroidAPIDAO.updateAcceleratorInfo", vo);
    }

    /**
     * 가속도 정보를 삭제한다.
     * @param vo - 삭제할 정보가 담긴 AcceleratorAPIVO
     * @return 등록 결과
     */
    public int deleteAcceleratorInfo(AcceleratorAndroidAPIVO vo) {
        return (Integer)delete("acceleratorAndroidAPIDAO.deleteAcceleratorInfo", vo);
    }

    /**
     * 가속도 정보를 조회한다.
     * @param vo - 조회할 정보가 담긴 AcceleratorAPIVO
     * @return 조회한 가속도 정보
     */
    public AcceleratorAndroidAPIVO selectAcceleratorInfo(AcceleratorAndroidAPIVO vo) {
        return (AcceleratorAndroidAPIVO) selectOne("acceleratorAndroidAPIDAO.selectAcceleratorInfo", vo);
    }

    /**
     * 가속도 정보 목록을 조회한다.
     * @param vo - 조회할 정보가 담긴 AcceleratorAPIDefaultVO
     * @return 가속도 정보 목록
     */
    public List<?> selectAcceleratorInfoList(AcceleratorAndroidAPIDefaultVO searchVO) {
        return selectList("acceleratorAndroidAPIDAO.selectAcceleratorInfoList", searchVO);
    }

    /**
     * 가속도 정보 총 갯수를 조회한다.
     * @param  vo - 조회할 정보가 담긴 AcceleratorAPIDefaultVO
     * @return 가속도 정보 총 갯수
     */
    public int selectAcceleratorInfoListTotCnt(AcceleratorAndroidAPIDefaultVO searchVO) {
        return (Integer) selectOne("acceleratorAndroidAPIDAO.selectAcceleratorInfoListTotCnt", searchVO);
    }

}
