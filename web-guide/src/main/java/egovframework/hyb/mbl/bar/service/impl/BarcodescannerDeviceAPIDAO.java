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
package egovframework.hyb.mbl.bar.service.impl;

import java.util.List;

import org.springframework.stereotype.Repository;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.mbl.bar.service.BarcodescannerAPIDefaultVO;
import egovframework.hyb.mbl.bar.service.BarcodescannerAPIVO;

/**
 * @Class Name : BarcodescannerDeviceAPIDAO.java
 * @Description : BarcodescannerDeviceAPIDAO Class
 * @Modification Information
 * @ @ 수정일 수정자 수정내용 @ --------- --------- ------------------------------- @
 *   2016.07.26 신성학 최초생성
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 07. 26
 * @version 1.0
 * @see
 * 
 * 		Copyright (C) by Ministry of Interior All right reserved.
 */

@Repository("BarcodescannerDeviceAPIDAO")
public class BarcodescannerDeviceAPIDAO extends EgovComAbstractDAO {

	/**
	 * BarcodescannerDevice 정보를 등록한다.
	 * 
	 * @param vo
	 *            - 등록할 정보가 담긴 BarcodescannerAPIVO
	 * @return 등록 결과
	 * @exception Exception
	 */
	public int insertBarcodescannerDevcie(BarcodescannerAPIVO vo) throws Exception {

		return (Integer) insert("barcodescannerDeviceAPIDAO.insertBarcodescannerDevcie", vo);

	}

	/**
	 * BarcodescannerDevice 정보를 조회한다.
	 * 
	 * @param vo
	 *            - 등록할 정보가 담긴 BarcodescannerAPIVO
	 * @return 등록 결과
	 * @exception Exception
	 */
	public List<?> selectBarcodescannerDevcieList(BarcodescannerAPIDefaultVO searchVO) throws Exception {

		return selectList("barcodescannerDeviceAPIDAO.selectBarcodescannerDevcieList", searchVO);
	}

}
