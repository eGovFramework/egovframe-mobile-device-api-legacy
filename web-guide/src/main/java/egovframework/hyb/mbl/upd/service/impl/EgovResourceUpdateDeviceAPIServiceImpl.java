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
package egovframework.hyb.mbl.upd.service.impl;

import javax.annotation.Resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import egovframework.hyb.ios.frw.service.impl.EgovFileMngiOSUtil;
import egovframework.hyb.mbl.upd.service.EgovResourceUpdateDeviceAPIService;
import egovframework.hyb.mbl.upd.service.ResourceUpdateDeviceAPIVO;
import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;

/**  
 * @Class Name : EgovPushDeviceAPIServiceImpl.java
 * @Description : EgovPushDeviceAPIServiceImpl Class
 * @Modification Information  
 * @
 * @  수정일       수정자                   수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2016.06.20   신용호                   최초생성
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 06.20
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by Ministry of Interior All right reserved.
 */

@Service("EgovResourceUpdateDeviceAPIService")
public class EgovResourceUpdateDeviceAPIServiceImpl extends EgovAbstractServiceImpl implements EgovResourceUpdateDeviceAPIService {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(EgovResourceUpdateDeviceAPIServiceImpl.class);

	/** ResUpdateDeviceAPIDAO */
    @Resource(name="ResourceUpdateDeviceAPIDAO")
    private ResourceUpdateDeviceAPIDAO resourceUpdateDeviceAPIDAO;

    @Resource(name = "egovFileMngiOSUtil")
    private EgovFileMngiOSUtil egovFileMngUtil;

    /**
	 * 알림 설정 정보 목록을 조회한다.
	 * @param VO - 조회할 정보가 담긴 ResourceUpdateDeviceAPIVO
	 * @return 알림 설정 정보 목록
	 * @exception Exception
	 */
    public ResourceUpdateDeviceAPIVO selectResourceUpdateVersionInfo(ResourceUpdateDeviceAPIVO searchVO) throws Exception {
        ResourceUpdateDeviceAPIVO resultVO = resourceUpdateDeviceAPIDAO.selectResourceUpdateVersionInfo(searchVO);
        if (resultVO != null && resultVO.getStreFileNm() != null && !resultVO.getStreFileNm().isEmpty()) {
        	try {
        		resultVO.setFileSha256(egovFileMngUtil.computeFileSha256(resultVO.getStreFileNm()));
        	} catch (Exception e) {
        		LOGGER.warn("Failed to compute resource update file SHA-256: {}", e.getMessage());
        		return null;
        	}
        }
        return resultVO;
    }
    
}
