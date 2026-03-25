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
package egovframework.hyb.ios.cps.web;

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

import egovframework.hyb.ios.cps.service.CompassiOSAPIDefaultVO;
import egovframework.hyb.ios.cps.service.CompassiOSAPIVO;
import egovframework.hyb.ios.cps.service.EgovCompassiOSAPIService;
import egovframework.rte.fdl.property.EgovPropertyService;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;

/**  
 * @Class Name : EgovCompassiOSAPIController
 * @Description : EgovCompassiOSAPIController Class
 * @Modification Information  
 * @
 * @ 수정일                수정자             수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.07.23   서형주              최초생성
 *   2012.08.27   서준식              json 형태로 변경
 *   2020.08.12   신용호              Swagger 적용
 * 
 * @author Device API 실행환경팀
 * @since 2012. 07. 30
 * @version 1.0
 * @see
 * 
 */

@Controller
public class EgovCompassIosAPIController {
	
	/** EgovCompassAPIService */
    @Resource(name = "EgovCompassiOSAPIService")
    private EgovCompassiOSAPIService egovCompassAPIService;
    
    /** propertiesService */
    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;
 
    /**
	 * 방향 정보 목록을 조회한다.
	 * @param searchVO - 조회할 정보가 담긴 CompassiOSAPIDefaultVO
	 * @param model
	 * @return "/cps/compassInfoList.do"
	 * @exception Exception
	 */
    @ApiOperation(value="디바이스 정보 목록조회", notes="[iOS] 디바이스 정보 목록을 조회한다.", response=CompassiOSAPIVO.class, responseContainer="List")
    @SuppressWarnings("unchecked")
	@RequestMapping(value="/cps/compassInfoList.do")
    public ModelAndView selectCompassInfoXMLList(@ModelAttribute("searchVO") CompassiOSAPIDefaultVO searchVO, 
    		ModelMap model)
            throws Exception {
    	
    	ModelAndView jsonView = new ModelAndView("jsonView"); 
 
		List<CompassiOSAPIVO> compassInfoList = (List<CompassiOSAPIVO>) egovCompassAPIService.selectCompassInfoList(searchVO);
		
		jsonView.addObject("compassInfoList", compassInfoList);
		jsonView.addObject("resultState","OK");
		return jsonView;
    }
    
    /**
	 * 방향 정보를 등록한다.
	 * @param searchVO - 등록할 정보가 담긴 CompassiOSAPIDefaultVO
	 * @param searchVO - 목록 조회조건 정보가 담긴 CompassiOSAPIDefaultVO
	 * @param status
	 * @return "forward:/cps/addCompassInfo.do"
	 * @exception Exception
	 */
    @ApiOperation(value="Compass 세부정보 등록", notes="[iOS] Compass 세부정보를 등록한다.\nresponseOK = {\"resultState\",\"OK\"}")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
    })
    @RequestMapping("/cps/addCompassInfo.do")
    public ModelAndView addCompassInfoXml(
       	 	CompassiOSAPIVO compassVO,
            BindingResult bindingResult, Model model, SessionStatus status) 
    		throws Exception {
    	
    	ModelAndView jsonView = new ModelAndView("jsonView"); 

		int success = egovCompassAPIService.insertCompassInfo(compassVO);
		
		if (success > 0) {
			jsonView.addObject("resultState","OK");
		} else {
			jsonView.addObject("resultState","FAIL");
		}

		return jsonView;
	}
    
    /**
	 * 방향 정보 목록을 삭제한다.
	 * @param sampleVO - 삭제할 정보가 담긴 VO
	 * @param searchVO - 목록 조회조건 정보가 담긴 VO
	 * @param status
	 * @return "forward:/cps/withdrawal.do"
	 * @exception Exception
	 */
    @ApiOperation(value="Compass 세부정보 삭제", notes="[iOS] Compass 세부정보를 삭제한다.\nresponseOK = {\"resultState\",\"OK\"}")
    @RequestMapping("/cps/withdrawal.do")
    public ModelAndView withdrawalXml(
       	 	CompassiOSAPIVO compassVO,
            BindingResult bindingResult, Model model, SessionStatus status) 
    throws Exception {
    	
    	ModelAndView jsonView = new ModelAndView("jsonView");
    	  	
    	int cnt = egovCompassAPIService.deleteCompassInfo(compassVO);
    	    	
    	if (cnt > 0) {
			jsonView.addObject("resultState","OK");
		} else {
			jsonView.addObject("resultState","FAIL");
		}
        
        return jsonView;
    }
    

}
