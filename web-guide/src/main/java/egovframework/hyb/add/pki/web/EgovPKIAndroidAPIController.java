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
package egovframework.hyb.add.pki.web;

import java.util.List;

import egovframework.com.cmm.security.DeviceAPIAuthSupport;
import egovframework.hyb.add.pki.service.EgovPKIAndroidAPIService;
import egovframework.hyb.add.pki.service.PKIAndroidAPIDefaultVO;
import egovframework.hyb.add.pki.service.PKIAndroidAPIVO;
import egovframework.hyb.add.pki.service.PKIAndroidAPIVOList;
import egovframework.rte.fdl.property.EgovPropertyService;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.support.SessionStatus;

@Controller
public class EgovPKIAndroidAPIController {

	@Resource(name = "EgovPKIAndroidAPIService")
	private EgovPKIAndroidAPIService egovPKIAPIService;

	@Resource(name = "propertiesService")
	protected EgovPropertyService propertiesService;

	@SuppressWarnings("unchecked")
	@RequestMapping("/pki/xml/pkiInfoList.do")
	public @ResponseBody
	PKIAndroidAPIVOList selectPKIInfoListXml(@ModelAttribute("searchPKIVO") PKIAndroidAPIDefaultVO searchVO,
			HttpServletRequest request, ModelMap model) throws Exception {

		DeviceAPIAuthSupport.ensureDeviceAccess(request);
		searchVO.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, searchVO.getUuid()));

		List<PKIAndroidAPIVO> pkiInfoList = (List<PKIAndroidAPIVO>) egovPKIAPIService.selectPKIInfoList(searchVO);

		PKIAndroidAPIVOList pkiAndroidAPIVOList = new PKIAndroidAPIVOList();
		pkiAndroidAPIVOList.setPKIInfoList(pkiInfoList);

		return pkiAndroidAPIVOList;
	}

	@RequestMapping("/pki/xml/addPKIInfo.do")
	public @ResponseBody
	PKIAndroidAPIVO addPKIInfoXml(@ModelAttribute("searchVO") PKIAndroidAPIDefaultVO searchVO, PKIAndroidAPIVO PKIVO,
			BindingResult bindingResult, HttpServletRequest request, Model model, SessionStatus status)
			throws Exception {

		DeviceAPIAuthSupport.ensureDeviceAccess(request);
		PKIVO.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, PKIVO.getUuid()));

		String sClientName = egovPKIAPIService.verifyCert(PKIVO);
		PKIAndroidAPIVO pkiAPIVO = new PKIAndroidAPIVO();

		if (sClientName.length() < 0) {
			pkiAPIVO.setResultState("FAIL");
			pkiAPIVO.setResultMessage("인증에 실패하였습니다.");
			return pkiAPIVO;
		}

		pkiAPIVO = PKIVO;
		pkiAPIVO.setDn(sClientName);
		pkiAPIVO.setSign(null);

		int success = egovPKIAPIService.insertPKIInfo(pkiAPIVO);
		if (success > 0) {
			pkiAPIVO.setResultState("OK");
			pkiAPIVO.setResultMessage("인증에 성공하였습니다.");
		} else {
			pkiAPIVO.setResultState("OK");
			pkiAPIVO.setResultMessage("저장에 실패하였습니다.");
		}

		return pkiAPIVO;
	}

}
