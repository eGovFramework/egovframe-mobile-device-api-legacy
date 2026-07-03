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
package egovframework.hyb.mbl.upd.web;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import egovframework.hyb.ios.frw.service.impl.EgovFileMngiOSUtil;
import egovframework.hyb.mbl.fop.service.FileOpenerDeviceAPIVO;
import egovframework.hyb.mbl.upd.service.EgovResourceUpdateDeviceAPIService;
import egovframework.hyb.mbl.upd.service.ResourceUpdateDeviceAPIVO;
/**  
 * @Class Name : EgovResUpdateAPIController
 * @Description : EgovResUpdateAPI Controller Class
 * @Modification Information  
 * @
 * @ 수정일         수정자             수정내용
 * @ ----------   --------------   -------------------------------
 *   2016.06.24   신용호             최초 작성
 *   2020.09.18   신용호             Swagger 적용
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 06. 24
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by Ministry of Interior All right reserved.
 */

@Controller
public class EgovResourceUpdateDeviceAPIController {
	
	private final Logger log = LoggerFactory.getLogger(this.getClass());
	
	/** EgovResUpdateDeviceAPIService */
    @Resource(name = "EgovResourceUpdateDeviceAPIService")
    private EgovResourceUpdateDeviceAPIService egovResourceUpdateDeviceAPIService;
    
	/** EgovFileMngUtil */
	@Resource(name = "egovFileMngiOSUtil")
	private EgovFileMngiOSUtil egovFileMngUtil;

    
    /**
	 * ResUpdate Version정보를 조회한다.
	 * @param searchVO - 조회할 정보가 담긴 ResourceUpdateDeviceAPIDefaultVO
	 * @param model
	 * @return ModelAndView
	 * @exception Exception
	 */
    @RequestMapping(value="/upd/ResourceUpdateVersionInfo.do")
    public ModelAndView selectVibratorInfoList(@ModelAttribute("resourceUpdateDeviceAPIDefaultVO") ResourceUpdateDeviceAPIVO searchVO, 
    		ModelMap model)
            throws Exception {
 
		ModelAndView jsonView = new ModelAndView("jsonView");
		ResourceUpdateDeviceAPIVO resourceUpdateDeviceAPIVO = egovResourceUpdateDeviceAPIService.selectResourceUpdateVersionInfo(searchVO);
		
		jsonView.addObject("result", resourceUpdateDeviceAPIVO);
		jsonView.addObject("resultState","OK");
		
		return jsonView;
    }

	/**
	 * 선택된 파일을 클라이언트로 전송한다.
	 * @param request -  HttpServletRequest 
	 * @param response - HttpServletResponse 
	 * @param fileVO - 전송할 파일 정보가 담긴 ResourceUpdateDeviceAPIVO 
	 * @return ModelAndView
	 * @exception Exception
	 */
    @RequestMapping("/upd/ResourceUpdatefileDownload.do")
	public void fileDownload(HttpServletRequest request, HttpServletResponse response, ResourceUpdateDeviceAPIVO fileVO) throws Exception{
		log.debug(">>> fileVO.getOrignlFileNm() = "+fileVO.getOrignlFileNm());
		log.debug(">>> fileVO.getStreFileNm() = "+fileVO.getStreFileNm());
		egovFileMngUtil.fileDownload(request, response, fileVO.getOrignlFileNm(), fileVO.getStreFileNm());
		
	}

}
