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
package egovframework.hyb.mbl.bar.service;

import java.util.List;

/**  
 * @Class Name : EgovBarcodescannerAPIService.java
 * @Description : EgovBarcodescannerAPIService Class
 * @Modification Information
 * @
 * @  수정일       수정자                 수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2016.07.26   신성학                 최초생성
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 07. 26
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by Ministry of Interior All right reserved.
 */

public interface EgovBarcodescannerAPIService {
	/**
	 * Barcodescanner을 위해 Barcodescanner 정보를 등록한다.
	 * @param vo - 등록할 정보가 담긴 BarcodescannerAPIVO
	 * @return 등록 결과
	 * @exception Exception
	 */
    int insertBarcodescannerDevcie(BarcodescannerAPIVO vo) throws Exception;

	/**
	 * Barcodescanner을 위해 Barcodescanner 정보를 서버에서 조회한다.
	 * @param vo - 등록할 정보가 담긴 BarcodescannerAPIVO
	 * @return 등록 결과
	 * @exception Exception
	 */
	List<?> selectBarcodescannerList(BarcodescannerAPIDefaultVO searchVO) throws Exception;

}
