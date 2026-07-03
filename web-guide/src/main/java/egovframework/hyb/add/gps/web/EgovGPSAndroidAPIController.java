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
package egovframework.hyb.add.gps.web;

import java.util.List;

import javax.annotation.Resource;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import egovframework.hyb.add.gps.service.EgovGPSAndroidAPIService;
import egovframework.hyb.add.gps.service.GPSAndroidAPIDefaultVO;
import egovframework.hyb.add.gps.service.GPSAndroidAPIVO;
import egovframework.hyb.add.gps.service.GPSAndroidAPIVOList;
import egovframework.rte.fdl.property.EgovPropertyService;
/**  
 * @Class Name : EgovGPSAndroidAPIController
 * @Description : EgovGPSAndroidAPIController Class
 * @Modification Information  
 * @
 * @ 수정일         수정자        수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.08.27   나신일        최초생성
 *   2020.08.24   신용호        Swagger 적용
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 08.27
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

@Controller
public class EgovGPSAndroidAPIController {

	/** EgovGPSAPIService */
	@Resource(name = "EgovGPSAndroidAPIService")
	private EgovGPSAndroidAPIService egovGPSAPIService;

	/** propertiesService */
	@Resource(name = "propertiesService")
	protected EgovPropertyService propertiesService;

	/**
	 * gps 정보 목록을 조회한다.
	 * 
	 * @param searchVO
	 *            - 조회할 정보가 담긴 GPSAndroidAPIDefaultVO
	 * @return GPSAndroidAPIVOList
	 * @exception Exception
	 */
    	@SuppressWarnings("unchecked")
	@RequestMapping(value = "/gps/xml/gpsInfoList.do")
	public @ResponseBody
	GPSAndroidAPIVOList selectGPSInfoListXml(GPSAndroidAPIDefaultVO searchVO) throws Exception {

		List<GPSAndroidAPIVO> gpsInfoList = (List<GPSAndroidAPIVO>) egovGPSAPIService.selectGPSInfoList(searchVO);
		GPSAndroidAPIVOList gpsAndroidAPIVOList = new GPSAndroidAPIVOList();
		gpsAndroidAPIVOList.setGpsInfoList(gpsInfoList);

		return gpsAndroidAPIVOList;
	}

	/**
	 * gps 정보를 등록한다.
	 * 
	 * @param insertVO
	 *            - 등록할 정보가 담긴 GPSAndroidAPIVO
	 * @return GPSAndroidAPIVO
	 * @exception Exception
	 */
    
	@RequestMapping("/gps/xml/addGPSInfo.do")
        	public @ResponseBody
	GPSAndroidAPIVO insertGPSInfo(GPSAndroidAPIVO insertVO) throws Exception {
		egovGPSAPIService.insertGPSInfo(insertVO);

		GPSAndroidAPIVO gpsAndroidAPIVO = new GPSAndroidAPIVO();
		gpsAndroidAPIVO.setResultState("OK");
		gpsAndroidAPIVO.setResultMessage("저장에 성공하였습니다.");
		return gpsAndroidAPIVO;
	}

	/**
	 * gps 정보 목록을 삭제한다.
	 * 
	 * @param deleteVO
	 *            - 삭제할 정보가 담긴 VO
	 * @return GPSAndroidAPIVO
	 * @exception Exception
	 */
    @RequestMapping("/gps/xml/deleteGPSInfo.do")
	public @ResponseBody
	GPSAndroidAPIVO deleteGPSInfo(GPSAndroidAPIVO deleteVO) throws Exception {

		int nCount = egovGPSAPIService.deleteGPSInfo(deleteVO);

		GPSAndroidAPIVO gpsAndroidAPIVO = new GPSAndroidAPIVO();
		if (nCount > 0) {
			gpsAndroidAPIVO.setResultState("OK");
			gpsAndroidAPIVO.setResultMessage("삭제에 성공하였습니다.");
		} else {
			gpsAndroidAPIVO.setResultState("FAIL");
			gpsAndroidAPIVO.setResultMessage("삭제에 실패하였습니다.");
		}
		return gpsAndroidAPIVO;
	}

}
