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
package egovframework.hyb.add.itf.service.impl;

import org.springframework.stereotype.Repository;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.add.itf.service.InterfaceAndroidAPIVO;

/**  
 * @Class Name : InterfaceAndroidAPIDAO.java
 * @Description : InterfaceAndroidAPIDAO DAO Class
 * @Modification Information  
 * @
 * @  수정일                 수정자                 수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2012.07.09    나신일                  최초생성
 * 
 * @author 모바일 디바이스 API 팀
 * @since 2012. 07. 09
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

@Repository("InterfaceAndroidAPIDAO")
public class InterfaceAndroidAPIDAO extends EgovComAbstractDAO {

    /**
     * 해당 ID로 가입된 정보가 있는지 확인 한다.
     * 
     * @param vo
     *            - 조회할 정보가 담긴 InterfaceAndroidAPIVO
     * @return 인터페이스 정보 갯수
     * @exception
     */
    public int selectInterfaceInfoListTotCnt(InterfaceAndroidAPIVO vo) {
        return (Integer) selectOne(
                "interfaceAndroidAPIDAO.selectInterfaceInfoListCnt", vo);
    }

    /**
     * 회원 정보를 등록한다.
     * 
     * @param vo
     *            - 등록할 정보가 담긴 InterfaceAndroidAPIVO
     * @return 등록 결과
     * @exception Exception
     */
    public int insertInterfaceInfo(InterfaceAndroidAPIVO vo) throws Exception {
        return (Integer) insert("interfaceAndroidAPIDAO.insertInterfaceInfo",
                vo);
    }

    /**
     * 로그인을 한다.
     * 
     * @param vo
     *            - 로그인할 정보가 담긴 InterfaceAndroidAPIVO
     * @return 로그인 결과
     * @exception Exception
     */
    public InterfaceAndroidAPIVO selectInterfaceInfo(InterfaceAndroidAPIVO vo)
            throws Exception {
        return (InterfaceAndroidAPIVO) selectOne(
                "interfaceAndroidAPIDAO.selectInterfaceInfo", vo);
    }

    public InterfaceAndroidAPIVO selectInterfaceInfoByUserId(InterfaceAndroidAPIVO vo)
            throws Exception {
        return (InterfaceAndroidAPIVO) selectOne(
                "interfaceAndroidAPIDAO.selectInterfaceInfoByUserId", vo);
    }

    /**
     * 회원탈퇴를 한다.
     * 
     * @param vo
     *            - 탈퇴할 정보가 담긴 InterfaceAndroidAPIVO
     * @return 회원탈퇴 결과
     * @exception Exception
     */
    public int deleteInterfaceInfo(InterfaceAndroidAPIVO vo) throws Exception {
        return delete("interfaceAndroidAPIDAO.deleteInterfaceInfo", vo);
    }

    public int deleteInterfaceInfoByUserId(InterfaceAndroidAPIVO vo) throws Exception {
        return delete("interfaceAndroidAPIDAO.deleteInterfaceInfoByUserId", vo);
    }

}
