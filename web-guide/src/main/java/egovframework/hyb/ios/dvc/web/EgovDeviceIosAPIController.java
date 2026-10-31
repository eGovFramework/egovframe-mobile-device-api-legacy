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
package egovframework.hyb.ios.dvc.web;

import java.util.List;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import egovframework.com.cmm.security.DeviceAPIAuthSupport;
import egovframework.hyb.ios.dvc.service.DeviceiOSAPIVO;
import egovframework.hyb.ios.dvc.service.EgovDeviceiOSAPIService;
import egovframework.rte.fdl.property.EgovPropertyService;
/**  
 * @Class Name : EgovDeviceiOSAPIController
 * @Description : EgovDeviceiOSAPIController Controller Class
 * @Modification Information  
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.07.30   서준식              최초 작성
 *   2020.08.10   신용호              Swagger 적용
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 07. 30
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

@RestController
public class EgovDeviceIosAPIController {
	
	/** EgovNetworkAPIService */
    @Resource(name = "egovDeviceiOSAPIService")
    private EgovDeviceiOSAPIService egovDeviceiOSAPIService;
    
    /** propertiesService */
    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;
 
    /**
	 * 디바이스 정보 목록을 조회한다.
	 * @param vo - 조회할 정보가 담긴 DeviceiOSAPIVO
	 * @param model
	 * @return ModelAndView
	 * @exception Exception
	 */
    @RequestMapping(value="/dvc/deviceInfoList.do")
    public ModelAndView selectDeviceList(DeviceiOSAPIVO vo)
            throws Exception {
 
		ModelAndView jsonView = new ModelAndView("jsonView");
		List<?> deviceInfoList = egovDeviceiOSAPIService.selectDeviceInfoList(vo);
		
		jsonView.addObject("deviceInfoList", deviceInfoList);
		jsonView.addObject("resultState","OK");
		
		return jsonView;
    }
    
    /**
	 * 디바이스 상세 정보를 조회한다.
	 * @param deviceiOSAPIVO - 조회할 정보가 담긴 DeviceiOSAPIVO
	 * @param model
	 * @return ModelAndView
	 * @exception Exception
	 */
    @RequestMapping(value="/dvc/deviceInfo.do")
    public ModelAndView selectDeviceInfo(DeviceiOSAPIVO vo, HttpServletRequest request)
            throws Exception {

		ModelAndView jsonView = new ModelAndView("jsonView");
		DeviceiOSAPIVO deviceiOSAPIVO = egovDeviceiOSAPIService.selectDeviceInfo(vo);
		if (deviceiOSAPIVO != null) {
			DeviceAPIAuthSupport.assertOwnedUuid(request, deviceiOSAPIVO.getUuid());
		}
		
		jsonView.addObject("deviceInfo", deviceiOSAPIVO);
		jsonView.addObject("resultState","OK");
		
		return jsonView;
    }
    
    /**
	 * 디바이스 정보를 등록한다.
	 * @param searchVO - 등록할 정보가 담긴 DeviceiOSAPIVO
	 * @param status
	 * @return ModelAndView
	 * @exception Exception
	 */
    @RequestMapping("/dvc/addDeviceInfo.do")
    public ModelAndView insertDeviceInfo(DeviceiOSAPIVO vo)
    throws Exception {
    	
    	ModelAndView jsonView = new ModelAndView("jsonView");
    	
    	egovDeviceiOSAPIService.insertDeviceInfo(vo);
        
        jsonView.addObject("resultState","OK");

        return jsonView;
    }
    
    /**
	 * 디바이스 정보 목록을 삭제한다.
	 * @param vo - 삭제할 정보가 담긴 DeviceiOSAPIVO
	 * @return ModelAndView
	 * @exception Exception
	 */
    @RequestMapping("/dvc/deleteDeviceInfo.do")
    public ModelAndView deleteDeviceInfo(DeviceiOSAPIVO vo, HttpServletRequest request)
            throws Exception {

    	DeviceiOSAPIVO deviceInfo = egovDeviceiOSAPIService.selectDeviceInfo(vo);
    	if (deviceInfo == null) {
    		ModelAndView deniedView = new ModelAndView("jsonView");
    		deniedView.addObject("resultState", "FAIL");
    		return deniedView;
    	}
    	DeviceAPIAuthSupport.assertOwnedUuid(request, deviceInfo.getUuid());
    	egovDeviceiOSAPIService.deleteDeviceInfo(deviceInfo);
        
        ModelAndView jsonView = new ModelAndView("jsonView");
        jsonView.addObject("resultState","OK");
 
        return jsonView;
    }

}
