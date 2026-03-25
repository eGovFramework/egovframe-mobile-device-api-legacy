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
package egovframework.hyb.ios.vbr.web;

import java.util.List;

import javax.annotation.Resource;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import egovframework.hyb.ios.vbr.service.EgovVibratoriOSAPIService;
import egovframework.hyb.ios.vbr.service.VibratoriOSAPIDefaultVO;
import egovframework.hyb.ios.vbr.service.VibratoriOSAPIVO;
import egovframework.rte.fdl.property.EgovPropertyService;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;

/**  
 * @Class Name : EgovVibratorAPIController
 * @Description : EgovVibratorAPI Controller Class
 * @Modification Information  
 * @
 * @ 수정일         수정자              수정내용
 * @ ----------   ---------------   -------------------------------
 *   2012.07.18   이해성              최초 작성
 *   2020.09.07   신용호              Swagger 적용
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 07. 18
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

@Controller
public class EgovVibratorIosAPIController {
	
	/** EgovVibratorIOSAPIService */
    @Resource(name = "EgovVibratoriOSAPIService")
    private EgovVibratoriOSAPIService egovVibratoriOSAPIService;
    
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
    @ApiOperation(value="Vibrator 알림설정 정보 목록조회", notes="[iOS] Vibrator 알림설정 정보 목록을 조회한다.", response=VibratoriOSAPIVO.class, responseContainer="List")
    @RequestMapping(value="/vbr/VibratoriOSInfoList.do")
    public ModelAndView selectVibratorInfoList(@ModelAttribute("searchVibratorVO") VibratoriOSAPIDefaultVO searchVO, 
    		ModelMap model)
            throws Exception {
 
		ModelAndView jsonView = new ModelAndView("jsonView");
		List<?> VibratorInfoList = egovVibratoriOSAPIService.selectVibratorList(searchVO);
		
		jsonView.addObject("VibratorInfoList", VibratorInfoList);
		jsonView.addObject("resultState","OK");
		
		return jsonView;
    } 
    
    /**
	 * 알림 설정 정보를 등록한다.
	 * @param searchVO - 등록할 정보가 담긴 VibratorAPIDefaultVO
	 * @param status
	 * @return ModelAndView
	 * @exception Exception
	 */
    @ApiOperation(value="Vibrator 알림설정 정보 등록", notes="[iOS] Vibrator 알림설정 정보를 등록한다.\nresponseOK = {\"message\",\"OK\"}")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
    })
    @RequestMapping("/vbr/addVibratoriOSInfo.do")
    public ModelAndView insertVibratorInfo(
       	 	VibratoriOSAPIVO sampleVO,
            BindingResult bindingResult, Model model, SessionStatus status) 
    throws Exception {
    	
    	ModelAndView jsonView = new ModelAndView("jsonView");
    	
    	int success = egovVibratoriOSAPIService.insertVibrator(sampleVO);
    	if(success > 0) {
			jsonView.addObject("resultState","OK");
			jsonView.addObject("resultMessage","insert success");
		} else {
			jsonView.addObject("resultState","FAIL");
			jsonView.addObject("resultMessage","insert fail");
		}

        return jsonView;
    }
}
