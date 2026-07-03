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
package egovframework.hyb.add.vbr.web;

import java.util.List;

import javax.annotation.Resource;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.support.SessionStatus;

import egovframework.hyb.add.vbr.service.EgovVibratorAndroidAPIService;
import egovframework.hyb.add.vbr.service.VibratorAndroidAPIDefaultVO;
import egovframework.hyb.add.vbr.service.VibratorAndroidAPIVO;
import egovframework.hyb.add.vbr.service.VibratorAndroidAPIXmlVO;
import egovframework.rte.fdl.property.EgovPropertyService;
/**  
 * @Class Name : EgovVibratorAndroidAPIController.java
 * @Description : EgovVibratorAndroidAPIController Class
 * @Modification Information  
 * @
 * @ 수정일         수정자              수정내용
 * @ ----------   --------------    -------------------------------
 *   2012.08.16   이율경              최초생성
 *   2020.09.07   신용호              Swagger 적용
 * 
 * @author 디바이스 API 실행환경 팀
 * @since 2012. 8. 16.
 * @version 1.0
 * @see
 * 
 */
@Controller
public class EgovVibratorAndroidAPIController {

	/** EgovVibratorAndroidAPIService */
	@Resource(name = "EgovVibratorAndroidAPIService")
	private EgovVibratorAndroidAPIService egovVibratorAndroidAPIService;

	/** propertiesService */
	@Resource(name = "propertiesService")
	protected EgovPropertyService propertiesService;

	/**
	 * 알림 설정 정보를 조회한다.
	 * @param searchVO - 조회할 정보가 담긴 VibratorAPIDefaultVO
	 * @param model
	 * @return ModelAndView
	 * @exception Exception
	 */
    	@SuppressWarnings("unchecked")
	@RequestMapping(value = "/vbr/VibratorAndroidInfoList.do")
	public @ResponseBody
	VibratorAndroidAPIXmlVO selectVibratorInfoList(@ModelAttribute("searchVibratorVO") VibratorAndroidAPIDefaultVO searchVO, ModelMap model) throws Exception {

		List<VibratorAndroidAPIVO> vibratorInfoList = (List<VibratorAndroidAPIVO>) egovVibratorAndroidAPIService.selectVibratorList(searchVO);

		VibratorAndroidAPIXmlVO vibratorAndroidAPIXmlVO = new VibratorAndroidAPIXmlVO();
		vibratorAndroidAPIXmlVO.setVibratorAndroidAPIList(vibratorInfoList);

		return vibratorAndroidAPIXmlVO;
	}

	/**
	 * 알림 설정 정보를 등록한다.
	 * @param searchVO - 등록할 정보가 담긴 VibratorAPIDefaultVO
	 * @param status
	 * @return ModelAndView
	 * @exception Exception
	 */
    @RequestMapping("/vbr/addVibratorAndroidInfo.do")
	public @ResponseBody
	VibratorAndroidAPIXmlVO insertVibratorInfo(
			VibratorAndroidAPIXmlVO vibratorVO,
			BindingResult bindingResult, Model model, SessionStatus status) throws Exception {

		VibratorAndroidAPIXmlVO xmlVO = new VibratorAndroidAPIXmlVO();

		int success = egovVibratorAndroidAPIService.insertVibrator(vibratorVO);
		if (success > 0) {

			xmlVO.setMessage("OK");
		} else {

			xmlVO.setMessage("FAIL");
		}

		return xmlVO;
	}
}
