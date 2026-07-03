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
package egovframework.hyb.add.dvc.web;

import java.util.List;

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

import egovframework.hyb.add.dvc.service.DeviceAndroidAPIDefaultVO;
import egovframework.hyb.add.dvc.service.DeviceAndroidAPIVO;
import egovframework.hyb.add.dvc.service.DeviceAndroidAPIVOList;
import egovframework.com.cmm.security.DeviceAPIAuthSupport;
import egovframework.hyb.add.dvc.service.EgovDeviceAndroidAPIService;
import egovframework.rte.fdl.property.EgovPropertyService;
/**  
 * @Class Name : EgovDeviceAPIController
 * @Description : EgovDeviceAPIController Class
 * @Modification Information  
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.07.23   서형주              최초생성
 *   2020.08.10   신용호              Swagger 적용
 * 
 * @author Device API 실행환경팀
 * @since 2012. 07. 23
 * @version 1.0
 * @see
 * 
 */

@Controller
public class EgovDeviceAndroidAPIController {
    
    /** egovDeviceAndroidAPIService */
    @Resource(name = "EgovDeviceAndroidAPIService")
    private EgovDeviceAndroidAPIService egovDeviceAndroidAPIService;
    
    /** propertiesService */
    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;
 
    /**
     * 디바이스 정보를 조회한다.
     * @param searchVO - 조회할 정보가 담긴 DeviceAPIDefaultVO
     * @param model
     * @return "/dvc/xml/deviceInfoList.do"
     * @exception Exception
     */
    @RequestMapping(value="/dvc/xml/deviceInfo.do")
    public @ResponseBody DeviceAndroidAPIVO selectDeviceInfoXML(@ModelAttribute("searchVO") DeviceAndroidAPIVO searchVO,
            HttpServletRequest request, ModelMap model)
            throws Exception {

        DeviceAndroidAPIVO deviceInfo = egovDeviceAndroidAPIService.selectDeviceInfo(searchVO);
        if (deviceInfo != null) {
            DeviceAPIAuthSupport.assertOwnedUuid(request, deviceInfo.getUuid());
        }
        return deviceInfo;
    }
    
    /**
     * 디바이스 정보 목록을 조회한다.
     * @param searchVO - 조회할 정보가 담긴 DeviceAPIDefaultVO
     * @param model
     * @return "/dvc/xml/deviceInfoList.do"
     * @exception Exception
     */
            @SuppressWarnings("unchecked")
	@RequestMapping(value="/dvc/xml/deviceInfoList.do")
    public @ResponseBody DeviceAndroidAPIVOList selectDeviceInfoXMLList(@ModelAttribute("searchVO") DeviceAndroidAPIDefaultVO searchVO, 
            ModelMap model)
            throws Exception {
        
        List<DeviceAndroidAPIVO> deviceInfoList = (List<DeviceAndroidAPIVO>) egovDeviceAndroidAPIService.selectDeviceInfoList(searchVO);
        
        DeviceAndroidAPIVOList deviceAndroidAPIVOList = new DeviceAndroidAPIVOList();
        
        deviceAndroidAPIVOList.setDeviceInfoList(deviceInfoList);
        
        return deviceAndroidAPIVOList;
    }
    
    /**
     * 디바이스 정보를 등록한다.
     * @param searchVO - 등록할 정보가 담긴 DeviceAPIDefaultVO
     * @param searchVO - 목록 조회조건 정보가 담긴 DeviceAPIDefaultVO
     * @param status
     * @return "forward:/dvc/xml/addDeviceInfo.do"
     * @exception Exception
     */
    @RequestMapping("/dvc/xml/addDeviceInfo.do")
    public @ResponseBody DeviceAndroidAPIVO addDeviceInfoXml(
                DeviceAndroidAPIVO deviceVO,
            BindingResult bindingResult, Model model, SessionStatus status) 
            throws Exception {

        DeviceAndroidAPIVO deviceAPIVO = new DeviceAndroidAPIVO();

        int success = egovDeviceAndroidAPIService.insertDeviceInfo(deviceVO);
        
        if (success > 0) {
            deviceAPIVO.setUseYn("OK");
        } else {
            deviceAPIVO.setUseYn("FAIL");
        }

        return deviceAPIVO;
    }
    
    /**
     * 디바이스 정보 목록을 삭제한다.
     * @param sampleVO - 삭제할 정보가 담긴 VO
     * @param searchVO - 목록 조회조건 정보가 담긴 VO
     * @param status
     * @return "forward:/dvc/xml/withdrawal.do"
     * @exception Exception
     */
    @RequestMapping("/dvc/xml/withdrawal.do")
    public @ResponseBody DeviceAndroidAPIVO withdrawalXml(
                DeviceAndroidAPIVO deviceVO,
            HttpServletRequest request,
            BindingResult bindingResult, Model model, SessionStatus status) 
    throws Exception {

        DeviceAndroidAPIVO deviceInfo = egovDeviceAndroidAPIService.selectDeviceInfo(deviceVO);
        if (deviceInfo == null) {
            DeviceAndroidAPIVO deviceAPIVO = new DeviceAndroidAPIVO();
            deviceAPIVO.setUseYn("FAIL");
            return deviceAPIVO;
        }
        DeviceAPIAuthSupport.assertOwnedUuid(request, deviceInfo.getUuid());
        int cnt = egovDeviceAndroidAPIService.deleteDeviceInfo(deviceInfo);
                
        DeviceAndroidAPIVO deviceAPIVO = new DeviceAndroidAPIVO();
        
        if(cnt > 0) {
            deviceAPIVO.setUseYn("OK");
        } else {
            deviceAPIVO.setUseYn("FAIL");
        }
        
        return deviceAPIVO;
    }
    

}
