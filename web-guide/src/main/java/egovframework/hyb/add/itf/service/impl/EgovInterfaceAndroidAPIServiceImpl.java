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

import egovframework.com.cmm.security.DeviceAPIPasswordUtil;
import egovframework.hyb.add.itf.service.EgovInterfaceAndroidAPIService;
import egovframework.hyb.add.itf.service.InterfaceAndroidAPIVO;

import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;

import javax.annotation.Resource;

import org.springframework.stereotype.Service;

@Service("EgovInterfaceAndroidAPIService")
public class EgovInterfaceAndroidAPIServiceImpl extends EgovAbstractServiceImpl
        implements EgovInterfaceAndroidAPIService {

    @Resource(name = "InterfaceAndroidAPIDAO")
    private InterfaceAndroidAPIDAO interfaceAPIDAO;

    public int selectInterfaceInfoListTotCnt(InterfaceAndroidAPIVO vo)
            throws Exception {
        return interfaceAPIDAO.selectInterfaceInfoListTotCnt(vo);
    }

    public int insertInterfaceInfo(InterfaceAndroidAPIVO vo) throws Exception {
        vo.setUserPw(DeviceAPIPasswordUtil.encode(vo.getUserPw()));
        return interfaceAPIDAO.insertInterfaceInfo(vo);
    }

    public InterfaceAndroidAPIVO selectInterfaceInfo(InterfaceAndroidAPIVO vo)
            throws Exception {
        InterfaceAndroidAPIVO stored = interfaceAPIDAO.selectInterfaceInfoByUserId(vo);
        if (stored == null) {
            return null;
        }
        if (!DeviceAPIPasswordUtil.matches(vo.getUserPw(), stored.getUserPw())) {
            return null;
        }
        stored.setUserPw(null);
        return stored;
    }

    public int deleteInterfaceInfo(InterfaceAndroidAPIVO vo) throws Exception {
        InterfaceAndroidAPIVO stored = interfaceAPIDAO.selectInterfaceInfoByUserId(vo);
        if (stored == null || !DeviceAPIPasswordUtil.matches(vo.getUserPw(), stored.getUserPw())) {
            return 0;
        }
        return interfaceAPIDAO.deleteInterfaceInfoByUserId(vo);
    }
}
