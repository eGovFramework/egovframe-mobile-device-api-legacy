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

@Controller
public class EgovPushDeviceAPIController {

    @Resource(name = "EgovPushDeviceAPIService")
    private EgovPushDeviceAPIService egovPushDeviceAPIService;

    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;

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
