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
package egovframework.hyb.ios.itf.service.impl;

import javax.annotation.Resource;

import org.springframework.stereotype.Service;

import egovframework.com.cmm.security.DeviceAPIPasswordUtil;
import egovframework.hyb.ios.itf.service.EgovInterfaceiOSAPIService;
import egovframework.hyb.ios.itf.service.InterfaceiOSAPIVO;
import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;

/**  
 * @Class Name : EgovInterfaceiOSAPIServiceImpl.java
 * @Description : EgovInterfaceiOSAPIServiceImpl Class
 * @Modification Information  
 * @
 * @  수정일                 수정자                 수정내용
 * @ 
 * @ 2012.07.11    이한철                  최초생성
 * 
 * @author 모바일 디바이스 API 팀
 * @since 2012. 07. 11
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

@Service("EgovInterfaceiOSAPIService")
public class EgovInterfaceiOSAPIServiceImpl extends EgovAbstractServiceImpl
        implements EgovInterfaceiOSAPIService {

    /** InterfaceiOSAPIDAO */
    @Resource(name = "InterfaceiOSAPIDAO")
    private InterfaceiOSAPIDAO interfaceAPIDAO;

    /**
     * 해당 ID로 가입된 정보가 있는지 확인 한다.
     * 
     * @param vo
     *            - 로그인할 정보가 담긴 InterfaceiOSAPIVO
     * @return 로그인 결과
     * @exception Exception
     */
    public int selectInterfaceInfoListTotCnt(InterfaceiOSAPIVO vo)
            throws Exception {
        return interfaceAPIDAO.selectInterfaceInfoListTotCnt(vo);
    }

    /**
     * 회원 정보를 등록한다.
     * 
     * @param vo
     *            - 등록할 정보가 담긴 InterfaceiOSAPIVO
     * @return 등록 결과
     * @exception Exception
     */
    public int insertInterfaceInfo(InterfaceiOSAPIVO vo) throws Exception {
        vo.setUserPw(DeviceAPIPasswordUtil.encode(vo.getUserPw()));
        return interfaceAPIDAO.insertInterfaceInfo(vo);
    }

    /**
     * 로그인을 한다.
     * 
     * @param vo
     *            - 로그인할 정보가 담긴 InterfaceiOSAPIVO
     * @return 로그인 결과
     * @exception Exception
     */
    public InterfaceiOSAPIVO selectInterfaceInfo(InterfaceiOSAPIVO vo)
            throws Exception {
        InterfaceiOSAPIVO stored = interfaceAPIDAO.selectInterfaceInfoByUserId(vo);
        if (stored == null) {
            return null;
        }
        if (!DeviceAPIPasswordUtil.matches(vo.getUserPw(), stored.getUserPw())) {
            return null;
        }
        stored.setUserPw(null);
        return stored;
    }

	/**
     * 회원탈퇴를 한다.
     * 
     * @param vo
     *            - 탈퇴할 정보가 담긴 InterfaceiOSAPIVO
     * @return 회원탈퇴 결과
     * @exception Exception
     */
    public int deleteInterfaceInfo(InterfaceiOSAPIVO vo) throws Exception {
        InterfaceiOSAPIVO stored = interfaceAPIDAO.selectInterfaceInfoByUserId(vo);
        if (stored == null || !DeviceAPIPasswordUtil.matches(vo.getUserPw(), stored.getUserPw())) {
            return 0;
        }
        return interfaceAPIDAO.deleteInterfaceInfoByUserId(vo);
    }
}
