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
package egovframework.hyb.mbl.fop.service.impl;

import java.util.List;

import javax.annotation.Resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import egovframework.hyb.mbl.fop.service.EgovFileOpenerDeviceAPIService;
import egovframework.hyb.mbl.fop.service.FileOpenerDeviceAPIDefaultVO;
import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;

/**  
 * @Class Name : EgovFileOpenerDeviceAPIServiceImpl.java
 * @Description : EgovFileOpenerDeviceAPIServiceImpl Class
 * @Modification Information  
 * @
 * @  수정일       수정자                   수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2016.07.11   장성호                   최초생성
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 07.11
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by Ministry of Interior All right reserved.
 */

@Service("EgovFileOpenerDeviceAPIService")
public class EgovFileOpenerDeviceAPIServiceImpl extends EgovAbstractServiceImpl implements EgovFileOpenerDeviceAPIService {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(EgovFileOpenerDeviceAPIServiceImpl.class);

	/** FileOpenerDeviceAPIDAO */
    @Resource(name="FileOpenerDeviceAPIDAO")
    private FileOpenerDeviceAPIDAO fileOpenerDeviceAPIDAO;

    /**
	 * 문서목록을 조회한다.
	 * @param VO - 조회할 정보가 담긴 FileOpenerDeviceAPIVO
	 * @return 문서 조회 목록 
	 * @exception Exception
	 */
    public List<?> selectFileOpenerDocumentListInfo(FileOpenerDeviceAPIDefaultVO searchVO) throws Exception {
		// TODO Auto-generated method stub
		return fileOpenerDeviceAPIDAO.selectFileOpenerDocumentList(searchVO);
	}
    
    
    
}
