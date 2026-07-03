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
package egovframework.hyb.ios.pki.web;

import java.util.List;

import egovframework.com.cmm.security.DeviceAPIAuthSupport;
import egovframework.hyb.ios.pki.service.EgovPKIiOSAPIService;
import egovframework.hyb.ios.pki.service.PKIiOSAPIDefaultVO;
import egovframework.hyb.ios.pki.service.PKIiOSAPIVO;

import egovframework.rte.fdl.property.EgovPropertyService;

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

@Controller
public class EgovPKIiOSAPIController {

    @Resource(name = "EgovPKIiOSAPIService")
    private EgovPKIiOSAPIService egovPKIAPIService;

    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;

    @RequestMapping(value = "/pki/pkiInfoList.do")
    public ModelAndView selectPKIInfoList(@ModelAttribute("searchPKIVO") PKIiOSAPIDefaultVO searchVO,
            HttpServletRequest request, ModelMap model) throws Exception {

        DeviceAPIAuthSupport.ensureDeviceAccess(request);
        searchVO.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, searchVO.getUuid()));

        ModelAndView jsonView = new ModelAndView("jsonView");
        List<?> pkiInfoList = egovPKIAPIService.selectPKIInfoList(searchVO);

        jsonView.addObject("pkiInfoList", pkiInfoList);
        jsonView.addObject("resultState", "OK");

        return jsonView;
    }

    @RequestMapping("/pki/addPKIiOSInfo.do")
    public ModelAndView addPKIInfo(@ModelAttribute("searchPKIVO") PKIiOSAPIDefaultVO searchVO, PKIiOSAPIVO PKIVO,
            BindingResult bindingResult, HttpServletRequest request, Model model, SessionStatus status)
            throws Exception {

        DeviceAPIAuthSupport.ensureDeviceAccess(request);
        PKIVO.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, PKIVO.getUuid()));

        String sClientName = egovPKIAPIService.verifyCert(PKIVO);
        ModelAndView jsonView = new ModelAndView("jsonView");

        if (sClientName == null) {
            jsonView.addObject("resultState", "FAIL");
            jsonView.addObject("resultMessage", "인증에 실패하였습니다.");
            return jsonView;
        }

        PKIVO.setDn(sClientName);

        int success = egovPKIAPIService.insertPKIInfo(PKIVO);
        if (success > 0) {
            jsonView.addObject("resultState", "OK");
            jsonView.addObject("dn", sClientName);
            jsonView.addObject("resultMessage", "인증에 성공하였습니다.");
        } else {
            jsonView.addObject("resultState", "FAIL");
            jsonView.addObject("resultMessage", "인증에 실패하였습니다.");
        }

        return jsonView;
    }

}
