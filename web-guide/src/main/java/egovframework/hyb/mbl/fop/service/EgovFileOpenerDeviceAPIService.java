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
package egovframework.hyb.mbl.fop.service;

import java.util.List;

/**  
 * @Class Name : EgovPushAPIService.java
 * @Description : EgovPushAPIService Class
 * @Modification Information
 * @
 * @  수정일       수정자                 수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2016.07.11   장성호                 최초생성
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 07. 11
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by Ministry of Interior All right reserved.
 */
public interface EgovFileOpenerDeviceAPIService {
	 
    
    /**
	 * Push Device 정보 목록을 조회한다.
	 * @param VO - 조회할 정보가 담긴 PushDeviceAPIDefaultVO
	 * @return 네트워크 정보 목록
	 * @exception Exception
	 */
	List<?> selectFileOpenerDocumentListInfo(FileOpenerDeviceAPIDefaultVO searchVO) throws Exception;
	
	//FileOpenerDeviceAPIVO selectFileOpenerDocumentListInfo(FileOpenerDeviceAPIVO searchVO) throws Exception;

}
