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
package egovframework.hyb.add.nwk.web;

import java.util.List;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.support.SessionStatus;

import egovframework.hyb.add.nwk.service.EgovNetworkAndroidAPIService;
import egovframework.hyb.add.nwk.service.NetworkAndroidAPIDefaultVO;
import egovframework.hyb.add.nwk.service.NetworkAndroidAPIVO;
import egovframework.hyb.add.nwk.service.NetworkAndroidAPIXmlVO;
import egovframework.rte.fdl.property.EgovPropertyService;
/**  
 * @Class Name : EgovNetworkAndroidAPIController.java
 * @Description : EgovNetworkAndroidAPIController Class
 * @Modification Information  
 * @
 * @ 수정일         수정자              수정내용
 * @ ----------   ---------------   -------------------------------
 *   2012.08.20   이율경              최초생성
 *   2020.09.07   신용호              Swagger 적용
 * 
 * @author 디바이스 API 실행환경 팀
 * @since 2012. 8. 20.
 * @version 1.0
 * @see
 * 
 */
@Controller
public class EgovNetworkAndroidAPIController {

	/** EgovNetworkAndroidAPIService */
	@Resource(name = "EgovNetworkAndroidAPIService")
	private EgovNetworkAndroidAPIService egovNetworkAndroidAPIService;

	/** propertiesService */
	@Resource(name = "propertiesService")
	protected EgovPropertyService propertiesService;

	/**
	 * 네트워크 정보 목록을 조회한다.
	 * @param searchVO - 조회할 정보가 담긴 NetworkAPIDefaultVO
	 * @param model
	 * @return ModelAndView
	 * @exception Exception
	 */
    	@SuppressWarnings("unchecked")
	@RequestMapping(value = "/nwk/networkAndroidInfoList.do")
	public @ResponseBody
	NetworkAndroidAPIXmlVO selectNetworkInfoList(@ModelAttribute("searchNetworkAndroidVO") NetworkAndroidAPIDefaultVO searchNetworkVO, ModelMap model) throws Exception {

		List<NetworkAndroidAPIVO> networkInfoList = (List<NetworkAndroidAPIVO>) egovNetworkAndroidAPIService.selectNetworkInfoList(searchNetworkVO);

		NetworkAndroidAPIXmlVO networkAndroidAPIXmlVO = new NetworkAndroidAPIXmlVO();
		networkAndroidAPIXmlVO.setNetworkInfoList(networkInfoList);

		return networkAndroidAPIXmlVO;
	}

	/**
	 * 네트워크 정보를 조회한다.
	 * @param searchVO - 조회할 정보가 담긴 NetworkAPIDefaultVO
	 * @param model
	 * @return ModelAndView
	 * @exception Exception
	 */
    @RequestMapping(value = "/nwk/networkAndroidInfo.do")
	public @ResponseBody
	NetworkAndroidAPIXmlVO selectNetworkInfo(
			NetworkAndroidAPIVO sampleNetworkVO,
			BindingResult bindingResult, Model model, SessionStatus status) throws Exception {

		NetworkAndroidAPIVO networkInfo = egovNetworkAndroidAPIService.selectNetworkInfo(sampleNetworkVO);

		NetworkAndroidAPIXmlVO networkAndroidAPIXmlVO = new NetworkAndroidAPIXmlVO();
		networkAndroidAPIXmlVO.setNetworkAndroidAPIVO(networkInfo);

		return networkAndroidAPIXmlVO;
	}

	/**
	 * 네트워크 정보를 등록한다.
	 * @param searchVO - 등록할 정보가 담긴 NetworkAPIDefaultVO
	 * @param status
	 * @return ModelAndView
	 * @exception Exception
	 */
    @RequestMapping("/nwk/addNetworkAndroidInfo.do")
	public @ResponseBody
	NetworkAndroidAPIXmlVO insertNetworkInfo(NetworkAndroidAPIVO sampleNetworkVO,
			BindingResult bindingResult, Model model, SessionStatus status) throws Exception {

		int success = egovNetworkAndroidAPIService.insertNetworkInfo(sampleNetworkVO);

		String successCode = "";
		if (success == 1) {

			successCode = "OK";
		} else {

			successCode = "FAIL";
		}

		NetworkAndroidAPIXmlVO networkAndroidAPIXmlVO = new NetworkAndroidAPIXmlVO();
		networkAndroidAPIXmlVO.setSuccessCode(successCode);

		return networkAndroidAPIXmlVO;
	}

	/**
	 * 네트워크 정보 목록을 삭제한다.
	 * @param sampleVO - 삭제할 정보가 담긴 VO
	 * @param status
	 * @return ModelAndView
	 * @exception Exception
	 */
    @RequestMapping("/nwk/deleteNetworkAndroidInfo.do")
	public @ResponseBody
	NetworkAndroidAPIXmlVO deleteNetworkInfo(NetworkAndroidAPIVO sampleVO, SessionStatus status)
			throws Exception {

		int success = egovNetworkAndroidAPIService.deleteNetworkInfo(sampleVO);

		String successCode = "";
		if (success == 1) {

			successCode = "OK";
		} else {

			successCode = "FAIL";
		}

		NetworkAndroidAPIXmlVO networkAndroidAPIXmlVO = new NetworkAndroidAPIXmlVO();
		networkAndroidAPIXmlVO.setSuccessCode(successCode);

		return networkAndroidAPIXmlVO;
	}

	/**
	 * 재생할 mp3 파일을 리턴한다
	 * @param sampleVO - 삭제할 정보가 담긴 VO
	 * @param status
	 * @return ModelAndView
	 * @exception Exception
	 */
    	@RequestMapping("/nwk/getMp3FileAndorid.do")
	public void getMp3File(HttpServletResponse response) throws Exception {

		String mp3FilePath = propertiesService.getString("fileStorePath");

		egovNetworkAndroidAPIService.selectMediaFileInf(response, mp3FilePath);
	}
}
