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
package egovframework.hyb.ios.gps.web;

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

import egovframework.hyb.ios.gps.service.EgovGPSiOSAPIService;
import egovframework.hyb.ios.gps.service.GPSiOSAPIDefaultVO;
import egovframework.hyb.ios.gps.service.GPSiOSAPIVO;
import egovframework.rte.fdl.property.EgovPropertyService;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;

/**  
 * @Class Name : EgovGPSAPIController
 * @Description : EgovGPSAPI Controller Class
 * @Modification Information  
 * @
 * @ 수정일         수정자        수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.07.31   이한철        최초 작성
 *   2020.08.24   신용호        Swagger 적용
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 06. 18
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

@Controller
public class EgovGPSIosAPIController {

    /** EgovGPSAPIService */
    @Resource(name = "EgovGPSAPIService")
    private EgovGPSiOSAPIService egovGPSAPIService;

    /** propertiesService */
    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;

    /**
     * gps 정보 목록을 조회한다.
     * 
     * @param searchVO
     *            - 조회할 정보가 담긴 GPSAPIDefaultVO
     * @param model
     * @return ModelAndView
     * @exception Exception
     */
    @ApiOperation(value="GPS 정보 목록조회", notes="[iOS] GPS 정보 목록을 조회한다.", response=GPSiOSAPIDefaultVO.class, responseContainer="List")
    @RequestMapping(value = "/gps/gpsInfoList.do")
    public ModelAndView selectGPSInfoList(
            @ModelAttribute("searchVO") GPSiOSAPIDefaultVO searchVO,
            ModelMap model) throws Exception {

        ModelAndView jsonView = new ModelAndView("jsonView");
        List<?> gpsInfoList = egovGPSAPIService.selectGPSInfoList(searchVO);

        jsonView.addObject("gpsInfoList", gpsInfoList);
        jsonView.addObject("resultState", "OK");

        return jsonView;
    }

    /**
     * gps 정보를 등록한다.
     * 
     * @param searchVO
     *            - 등록할 정보가 담긴 GPSAPIDefaultVO
     * @param status
     * @return ModelAndView
     * @exception Exception
     */
    @ApiOperation(value="GPS 세부정보 등록", notes="[iOS] GPS 세부정보를 등록한다.\nresponseOK = {\"resultState\",\"OK\"}")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
    })
    @RequestMapping("/gps/addGPSInfo.do")
    public ModelAndView insertGPSInfo(
            @ModelAttribute("searchVO") GPSiOSAPIDefaultVO searchVO,
            GPSiOSAPIVO sampleVO, BindingResult bindingResult, Model model,
            SessionStatus status) throws Exception {

        /*
         * if (bindingResult.hasErrors()) { model.addAttribute("sampleVO",
         * sampleVO); return "/sample/egovSampleRegister"; }
         */

        ModelAndView jsonView = new ModelAndView("jsonView");

        egovGPSAPIService.insertGPSInfo(sampleVO);

        jsonView.addObject("resultState", "OK");
        jsonView.addObject("resultMessage", "추가되었습니다.");

        return jsonView;
    }

    /**
     * gps 정보 목록을 삭제한다.
     * 
     * @param sampleVO
     *            - 삭제할 정보가 담긴 VO
     * @param status
     * @return ModelAndView
     * @exception Exception
     */
    @ApiOperation(value="GPS 세부정보 삭제", notes="[iOS] GPS 세부정보를 삭제한다.\nresponseOK = {\"resultState\",\"OK\"}")
    @ApiImplicitParams({
    	@ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
    })
    @RequestMapping("/gps/deleteGPSInfo.do")
    public ModelAndView deleteGPSInfo(GPSiOSAPIVO sampleVO,
            @ModelAttribute("searchVO") GPSiOSAPIDefaultVO searchVO,
            SessionStatus status) throws Exception {

        egovGPSAPIService.deleteGPSInfo(sampleVO);

        ModelAndView jsonView = new ModelAndView("jsonView");
        jsonView.addObject("resultState", "OK");
        jsonView.addObject("resultMessage", "삭제되었습니다.");

        return jsonView;
    }

}
