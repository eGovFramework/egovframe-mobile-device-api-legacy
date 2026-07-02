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
package egovframework.hyb.mbl.pus.web;

import java.util.List;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import egovframework.com.cmm.security.DeviceAPIAuthSupport;
import egovframework.hyb.mbl.pus.service.EgovPushDeviceAPIService;
import egovframework.hyb.mbl.pus.service.PushDeviceAPIDefaultVO;
import egovframework.hyb.mbl.pus.service.PushDeviceAPIVO;
import egovframework.rte.fdl.property.EgovPropertyService;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;

/**  
 * @Class Name : EgovPushDeviceAPIController
 * @Description : EgovPushDeviceAPIController Class
 * @Modification Information  
 * @
 * @ 수정일                수정자             수정내용
 * @ ----------   ---------   -------------------------------
 *   2016.06.20   신성학              최초 작성
 *   2020.09.16   신용호              Swagger 적용
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 06. 20
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by Ministry of Interior All right reserved.
 */

@Controller
public class EgovPushDeviceAPIController {
	
	/** EgovPushDeviceAPIService */
    @Resource(name = "EgovPushDeviceAPIService")
    private EgovPushDeviceAPIService egovPushDeviceAPIService;
    
    /** propertiesService */
    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;
 
    /**
	 * Push Device 목록을 조회한다.
	 * @param searchVO - 조회할 정보가 담긴 PushDeviceAPIDefaultVO
	 * @param model
	 * @return ModelAndView
	 * @exception Exception
	 */
    @ApiOperation(value = "Push Notification 정보 목록조회", notes = "Push Notification 정보 목록을 조회한다.", response = PushDeviceAPIVO.class, responseContainer = "List")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
    })
    @RequestMapping(value = "/pus/pushDeviceInfoList.do")
    public ModelAndView selectVibratorInfoList(@ModelAttribute("searchVO") PushDeviceAPIDefaultVO searchVO,
            HttpServletRequest request, ModelMap model) throws Exception {

        DeviceAPIAuthSupport.ensureDeviceAccess(request);
        searchVO.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, searchVO.getUuid()));

        ModelAndView jsonView = new ModelAndView("jsonView");
        List<?> pushDeviceInfoList = egovPushDeviceAPIService.selectPushDeviceList(searchVO);

        jsonView.addObject("pushDeviceInfoList", pushDeviceInfoList);
        jsonView.addObject("resultState", "OK");

        return jsonView;
    }

    /**
	 * Push Notification을 위하여 Device정보를 등록한다.
	 * @param searchVO - 등록할 정보가 담긴 PushDeviceAPIVO
	 * @param status
	 * @return ModelAndView
	 * @exception Exception
	 */
    @ApiOperation(value = "Push Notification 세부정보 등록", notes = "Push Notification 세부정보를 등록한다.\nresponseOK = {\"resultState\",\"OK\"}")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
    })
    @RequestMapping("/pus/addPushDeviceInfo.do")
    public ModelAndView insertDeviceInfo(PushDeviceAPIVO sampleVO, BindingResult bindingResult,
            HttpServletRequest request, Model model, SessionStatus status) throws Exception {

        DeviceAPIAuthSupport.ensureDeviceAccess(request);
        sampleVO.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, sampleVO.getUuid()));

        ModelAndView jsonView = new ModelAndView("jsonView");

        int success = egovPushDeviceAPIService.insertPushDevice(sampleVO);
        if (success > 0) {
            jsonView.addObject("resultState", "OK");
            jsonView.addObject("resultMessage", "insert success");
        } else {
            jsonView.addObject("resultState", "FAIL");
            jsonView.addObject("resultMessage", "insert fail");
        }

        return jsonView;
    }


    /**
	 * Push Notification을 서버에 요청한다.
	 * @param searchVO - 등록할 정보가 담긴 PushDeviceAPIVO
	 * @param status
	 * @return ModelAndView
	 * @exception Exception
	 */
    @ApiOperation(value = "Push Notification 발송메시지정보 등록", notes = "Push Notification 발송메시지정보를 등록한다.\nresponseOK = {\"resultState\",\"OK\"}")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
            @ApiImplicitParam(name = "osType", value = "OS 구분", required = true, dataType = "string", paramType = "query"),
    })
    @RequestMapping("/pus/requestPushInfo.do")
    public ModelAndView insertVibratorInfo(PushDeviceAPIVO sampleVO, BindingResult bindingResult,
            HttpServletRequest request, Model model, SessionStatus status) throws Exception {

        DeviceAPIAuthSupport.ensureDeviceAccess(request);
        sampleVO.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, sampleVO.getUuid()));

        ModelAndView jsonView = new ModelAndView("jsonView");

        int success = egovPushDeviceAPIService.insertPushInfo(sampleVO);
        if (success > 0) {
            jsonView.addObject("resultState", "OK");
            jsonView.addObject("resultMessage", "insert success");
        } else {
            jsonView.addObject("resultState", "FAIL");
            jsonView.addObject("resultMessage", "insert fail");
        }

        return jsonView;
    }

    /**
	 * Push Notification 세부정보를 조회한다.
	 * @param searchVO - 조회할 정보가 담긴 PushDeviceAPIDefaultVO
	 * @param model
	 * @return ModelAndView
	 * @exception Exception
	 */
    @ApiOperation(value = "Push Notification 세부정보 조회", notes = "Push Notification 세부정보를 조회한다.", response = PushDeviceAPIVO.class)
    @ApiImplicitParams({
            @ApiImplicitParam(name = "sn", value = "일련번호", required = true, dataType = "int", paramType = "query"),
            @ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
    })
    @RequestMapping(value = "/pus/pushDeviceInfo.do")
    public ModelAndView selectVibratorInfo(@ModelAttribute("searchVO") PushDeviceAPIVO searchVO,
            HttpServletRequest request, ModelMap model) throws Exception {

        DeviceAPIAuthSupport.ensureDeviceAccess(request);
        searchVO.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, searchVO.getUuid()));

        ModelAndView jsonView = new ModelAndView("jsonView");
        PushDeviceAPIVO pushDeviceAPIVO = egovPushDeviceAPIService.selectPushDevice(searchVO);
        if (pushDeviceAPIVO != null) {
            DeviceAPIAuthSupport.assertOwnedUuid(request, pushDeviceAPIVO.getUuid());
        }

        jsonView.addObject("pushDeviceInfo", pushDeviceAPIVO);
        jsonView.addObject("resultState", "OK");

        return jsonView;
    }
    
    /**
	 * Push 송신 메세지 목록을 조회한다.
	 * @param searchVO - 조회할 정보가 담긴 PushDeviceAPIDefaultVO
	 * @param model
	 * @return ModelAndView
	 * @exception Exception
	 */
    @ApiOperation(value = "Push Notification 송신메시지 세부정보 조회", notes = "Push Notification 송신메시지 세부정보를 조회한다.", response = PushDeviceAPIVO.class)
    @ApiImplicitParams({
            @ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
    })
    @RequestMapping(value = "/pus/PushMessageList.do")
    public ModelAndView selectPushMessageList(@ModelAttribute("searchVO") PushDeviceAPIVO searchVO,
            HttpServletRequest request, ModelMap model) throws Exception {

        DeviceAPIAuthSupport.ensureDeviceAccess(request);
        searchVO.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, searchVO.getUuid()));

        ModelAndView jsonView = new ModelAndView("jsonView");
        List<?> pushMessageList = egovPushDeviceAPIService.selectPushMessageList(searchVO);

        jsonView.addObject("PushMessageList", pushMessageList);
        jsonView.addObject("resultState", "OK");

        return jsonView;
    }
}
