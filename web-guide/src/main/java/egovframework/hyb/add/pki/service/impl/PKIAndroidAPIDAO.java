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
package egovframework.hyb.add.pki.service.impl;

import java.util.List;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.add.pki.service.PKIAndroidAPIDefaultVO;
import egovframework.hyb.add.pki.service.PKIAndroidAPIVO;

import org.springframework.stereotype.Repository;

/**  
 * @Class Name : PKIAndroidAPIDAO.java
 * @Description : PKIAndroidAPIDAO DAO Class
 * @Modification Information  
 * @
 * @  수정일                 수정자                 수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2012.07.23    나신일                  최초생성
 * 
 * @author 모바일 디바이스 API 팀
 * @since 2012. 07. 23
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

@Repository("PKIAndroidAPIDAO")
public class PKIAndroidAPIDAO extends EgovComAbstractDAO {

    /**
     * 인증서로그인한 정보를 등록한다.
     * 
     * @param vo
     *            - 등록할 정보가 담긴 PKIAndroidAPIVO
     * @return 등록 결과
     * @exception Exception
     */
    public int insertPKIInfo(PKIAndroidAPIVO vo) throws Exception {
        return (Integer) insert("PKIAndroidAPIDAO.insertPKIInfo", vo);
    }

    /**
     * pki 정보 목록을 조회한다.
     * 
     * @param vo
     *            - 조회할 정보가 담긴 PKIAndroidAPIDefaultVO
     * @return pki 정보 목록
     * @exception Exception
     */
    public List<?> selectPKIInfoList(PKIAndroidAPIDefaultVO searchVO)
            throws Exception {
        return selectList("PKIAndroidAPIDAO.selectPKIInfoList", searchVO);
    }

    /**
     * pki 정보 총 갯수를 조회한다.
     * 
     * @param vo
     *            - 조회할 정보가 담긴 PKIAndroidAPIDefaultVO
     * @return pki 정보 총 갯수
     * @exception
     */
    public int selectPKIInfoListTotCnt(PKIAndroidAPIDefaultVO searchVO) {
        return (Integer) selectOne(
                "PKIAndroidAPIDAO.selectPKIInfoListTotCnt", searchVO);
    }

}
