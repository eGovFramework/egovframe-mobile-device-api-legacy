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
package egovframework.hyb.add.cps.web;

import java.util.List;

import egovframework.hyb.add.cps.service.CompassAndroidAPIDefaultVO;
import egovframework.hyb.add.cps.service.CompassAndroidAPIVO;
import egovframework.hyb.add.cps.service.CompassAndroidAPIVOList;
import egovframework.hyb.add.cps.service.EgovCompassAndroidAPIService;
import egovframework.rte.fdl.property.EgovPropertyService;
import javax.annotation.Resource;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.support.SessionStatus;

/**  
 * @Class Name : EgovCompassAPIController
 * @Description : EgovCompassAPIController Class
 * @Modification Information  
 * @
 * @ 수정일                수정자             수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.07.23   서형주              최초생성
 *   2020.08.12   신용호              Swagger 적용
 * 
 * @author Device API 실행환경팀
 * @since 2012. 07. 30
 * @version 1.0
 * @see
 * 
 */

@Controller
public class EgovCompassAndroidAPIController {
    
    /** egovCompassAndroidAPIService */
    @Resource(name = "EgovCompassAndroidAPIService")
    private EgovCompassAndroidAPIService egovCompassAndroidAPIService;
    
    /** propertiesService */
    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;
 
    /**
     * 방향 정보 목록을 조회한다.
     * @param searchVO - 조회할 정보가 담긴 CompassAPIDefaultVO
     * @param model
     * @return "/cps/xml/compassInfoList.do"
     * @exception Exception
     */
        @SuppressWarnings("unchecked")
	@RequestMapping(value="/cps/xml/compassInfoList.do")
    public @ResponseBody CompassAndroidAPIVOList selectCompassInfoXMLList(@ModelAttribute("searchVO") CompassAndroidAPIDefaultVO searchVO, 
            ModelMap model)
            throws Exception {
 
        List<CompassAndroidAPIVO> compassInfoList = (List<CompassAndroidAPIVO>) egovCompassAndroidAPIService.selectCompassInfoList(searchVO);
        
        CompassAndroidAPIVOList compassAndroidAPIVOList = new CompassAndroidAPIVOList();
        
        compassAndroidAPIVOList.setCompassInfoList(compassInfoList);
        
        return compassAndroidAPIVOList;
    }
    
    /**
     * 방향 정보를 등록한다.
     * @param searchVO - 등록할 정보가 담긴 CompassAPIDefaultVO
     * @param searchVO - 목록 조회조건 정보가 담긴 CompassAPIDefaultVO
     * @param status
     * @return "forward:/cps/xml/addCompassInfo.do"
     * @exception Exception
     */
    @RequestMapping("/cps/xml/addCompassInfo.do")
    public @ResponseBody CompassAndroidAPIVO addCompassInfoXml(
                CompassAndroidAPIVO compassVO,
            BindingResult bindingResult, Model model, SessionStatus status) 
            throws Exception {

        CompassAndroidAPIVO compassAPIVO = new CompassAndroidAPIVO();

        int success = egovCompassAndroidAPIService.insertCompassInfo(compassVO);
        
        if (success > 0) {
            compassAPIVO.setUseYn("OK");
        } else {
            compassAPIVO.setUseYn("FAIL");
        }

        return compassAPIVO;
    }
    
    /**
     * 방향 정보 목록을 삭제한다.
     * @param sampleVO - 삭제할 정보가 담긴 VO
     * @param searchVO - 목록 조회조건 정보가 담긴 VO
     * @param status
     * @return "forward:/cps/xml/withdrawal.do"
     * @exception Exception
     */
    @RequestMapping("/cps/xml/withdrawal.do")
    public @ResponseBody CompassAndroidAPIVO withdrawalXml(
                CompassAndroidAPIVO compassVO,
            BindingResult bindingResult, Model model, SessionStatus status) 
    throws Exception {        
              
        int cnt = egovCompassAndroidAPIService.deleteCompassInfo(compassVO);
                
        CompassAndroidAPIVO compassAPIVO = new CompassAndroidAPIVO();
        
        if(cnt > 0) {
            compassAPIVO.setUseYn("OK");
        } else {
            compassAPIVO.setUseYn("FAIL");
        }
        
        return compassAPIVO;
    }
    

}
