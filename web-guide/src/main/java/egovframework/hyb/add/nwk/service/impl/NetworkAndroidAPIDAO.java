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
package egovframework.hyb.add.nwk.service.impl;

import java.util.List;

import org.springframework.stereotype.Repository;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.add.nwk.service.NetworkAndroidAPIDefaultVO;
import egovframework.hyb.add.nwk.service.NetworkAndroidAPIVO;

/**  
 * @Class Name : NetworkAndroidAPIDAO.java
 * @Description : NetworkAndroidAPIDAO Class
 * @Modification Information  
 * @
 * @  수정일            수정자        수정내용
 * @ ---------        ---------    -------------------------------
 * @ 2012. 8. 20.        이율경        최초생성
 * @ 2026. 6. 26.        이백행        [2026년 컨트리뷰션] 불필요한 예외(throws Exception) 제거
 * 
 * @author 디바이스 API 실행환경 팀
 * @since 2012. 8. 20.
 * @version 1.0
 * @see
 * 
 */
@Repository("NetworkAndroidAPIDAO")
public class NetworkAndroidAPIDAO extends EgovComAbstractDAO {

    /**
     * 네트워크 정보를 등록한다.
     * @param vo - 등록할 정보가 담긴 NetworkAPIVO
     * @return 등록 결과
     */
    public int insertNetworkInfo(NetworkAndroidAPIVO vo) {
        return (Integer)insert("networkAndroidAPIDAO.insertNetworkInfo", vo);
    }

    /**
     * 네트워크 정보를 수정한다.
     * @param vo - 수정할 정보가 담긴 NetworkAPIVO
     * @return void형
     */
    public int updateNetworkInfo(NetworkAndroidAPIVO vo) {
        return (Integer)update("networkAndroidAPIDAO.updateNetworkInfo", vo);
    }

    /**
     * 네트워크 정보를 삭제한다.
     * @param vo - 삭제할 정보가 담긴 NetworkAPIVO
     * @return void형 
     */
    public int deleteNetworkInfo(NetworkAndroidAPIVO vo) {
        return (Integer)delete("networkAndroidAPIDAO.deleteNetworkInfo", vo);
    }

    /**
     * 네트워크 정보를 조회한다.
     * @param vo - 조회할 정보가 담긴 NetworkAPIVO
     * @return 조회한 네트워크 정보
     */
    public NetworkAndroidAPIVO selectNetworkInfo(NetworkAndroidAPIVO vo) {
        return (NetworkAndroidAPIVO) selectOne("networkAndroidAPIDAO.selectNetworkInfo", vo);
    }

    /**
     * 네트워크 정보 목록을 조회한다.
     * @param vo - 조회할 정보가 담긴 NetworkAPIDefaultVO
     * @return 네트워크 정보 목록
     */
    public List<?> selectNetworkInfoList(NetworkAndroidAPIDefaultVO searchNetworkVO) {
        return selectList("networkAndroidAPIDAO.selectNetworkInfoList", searchNetworkVO);
        //return null;
    }

    /**
     * 네트워크 정보 총 갯수를 조회한다.
     * @param  vo - 조회할 정보가 담긴 NetworkAPIDefaultVO
     * @return 네트워크 정보 총 갯수
     */
    public int selectNetworkInfoListTotCnt(NetworkAndroidAPIDefaultVO searchVO) {
        return (Integer) selectOne("networkAPIDAO.selectNetworkInfoListTotCnt_S", searchVO);
    }

}
