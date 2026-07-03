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
package egovframework.hyb.add.acl.web;

import java.util.List;

import javax.annotation.Resource;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.support.SessionStatus;

import egovframework.hyb.add.acl.service.AcceleratorAndroidAPIDefaultVO;
import egovframework.hyb.add.acl.service.AcceleratorAndroidAPIVO;
import egovframework.hyb.add.acl.service.AcceleratorAndroidAPIVOList;
import egovframework.hyb.add.acl.service.EgovAcceleratorAndroidAPIService;
import egovframework.rte.fdl.property.EgovPropertyService;
/**  
 * @Class Name : EgovAcceleratorAPIController
 * @Description : EgovAcceleratorAPIController Class
 * @Modification Information  
 * @
 * @ 수정일                수정자             수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.07.23   서형주              최초생성
 *   2020.08.11   신용호              Swagger 적용
 * 
 * @author Device API 실행환경팀
 * @since 2012. 07. 23
 * @version 1.0
 * @see
 * 
 */

@Controller
public class EgovAcceleratorAndroidAPIController {
    
    /** egovAcceleratorAndroidAPIService */
    @Resource(name = "EgovAcceleratorAndroidAPIService")
    private EgovAcceleratorAndroidAPIService egovAcceleratorAndroidAPIService;
    
    /** propertiesService */
    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;
 
    /**
     * 가속도 정보 목록을 조회한다.
     * @param searchVO - 조회할 정보가 담긴 AcceleratorAPIDefaultVO
     * @param model
     * @return "/acl/xml/acceleratorInfoList.do"
     * @exception Exception
     */
        @SuppressWarnings("unchecked")
	@RequestMapping(value="/acl/xml/acceleratorInfoList.do")
    public @ResponseBody AcceleratorAndroidAPIVOList selectAcceleratorInfoXMLList(
    		@ModelAttribute("searchVO") AcceleratorAndroidAPIDefaultVO searchVO, ModelMap model)
            throws Exception {
 
        List<AcceleratorAndroidAPIVO> acceleratorInfoList = (List<AcceleratorAndroidAPIVO>) egovAcceleratorAndroidAPIService.selectAcceleratorInfoList(searchVO);
        
        AcceleratorAndroidAPIVOList acceleratorAndroidAPIVOList = new AcceleratorAndroidAPIVOList();
        
        acceleratorAndroidAPIVOList.setAcceleratorInfoList(acceleratorInfoList);
        
        return acceleratorAndroidAPIVOList;
    }
    
    /**
     * 가속도 정보를 등록한다.
     * @param searchVO - 등록할 정보가 담긴 AcceleratorAPIDefaultVO
     * @param searchVO - 목록 조회조건 정보가 담긴 AcceleratorAPIDefaultVO
     * @param status
     * @return "forward:/acl/xml/addAcceleratorInfo.do"
     * @exception Exception
     */
    @RequestMapping("/acl/xml/addAcceleratorInfo.do")
    public @ResponseBody AcceleratorAndroidAPIVO addAcceleratorInfoXml(
                AcceleratorAndroidAPIVO acceleratorVO,
            BindingResult bindingResult, Model model, SessionStatus status)
            throws Exception {

        AcceleratorAndroidAPIVO acceleratorAPIVO = new AcceleratorAndroidAPIVO();

        int success = egovAcceleratorAndroidAPIService.insertAcceleratorInfo(acceleratorVO);
        
        if (success > 0) {
            acceleratorAPIVO.setUseYn("OK");
        } else {
            acceleratorAPIVO.setUseYn("FAIL");
        }

        return acceleratorAPIVO;
    }
    
    /**
     * 가속도 정보 목록을 삭제한다.
     * @param sampleVO - 삭제할 정보가 담긴 VO
     * @param searchVO - 목록 조회조건 정보가 담긴 VO
     * @param status
     * @return "forward:/acl/xml/withdrawal.do"
     * @exception Exception
     */
    @RequestMapping("/acl/xml/withdrawal.do")
    public @ResponseBody AcceleratorAndroidAPIVO withdrawalXml(
                AcceleratorAndroidAPIVO acceleratorVO,
            BindingResult bindingResult, Model model, SessionStatus status) 
    throws Exception {
        
        int cnt = egovAcceleratorAndroidAPIService.deleteAcceleratorInfo(acceleratorVO);
        
        AcceleratorAndroidAPIVO acceleratorAPIVO = new AcceleratorAndroidAPIVO();
        
        if(cnt > 0) {
            acceleratorAPIVO.setUseYn("OK");
        } else {
            acceleratorAPIVO.setUseYn("FAIL");
        }
        
        return acceleratorAPIVO;
    }
    

}
