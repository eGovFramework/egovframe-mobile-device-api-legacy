package egovframework.hyb.mbl.jai.web;

import java.util.List;

import javax.annotation.Resource;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import egovframework.hyb.mbl.jai.service.EgovJailbreakDetectionDeviceAPIService;
import egovframework.hyb.mbl.jai.service.JailbreakDetectionDeviceAPIDefaultVO;
import egovframework.hyb.mbl.jai.service.JailbreakDetectionDeviceAPIVO;
import egovframework.rte.fdl.property.EgovPropertyService;
/**  
 * @Class Name : EgovJailbreakDetectionDeviceAPIController
 * @Description : EgovJailbreakDetectionDeviceAPIController Class
 * @Modification Information  
 * @
 * @ 수정일         수정자              수정내용
 * @ ----------   ---------------   -------------------------------
 *   2016.07.26   신성학              최초 작성
 *   2020.09.18   신용호              Swagger 적용
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 07. 26
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by Ministry of Interior All right reserved.
 */

@Controller
public class EgovJailbreakDetectionDeviceAPIController {
	
	/** EgovJailbreakDetectionDeviceAPIService */
    @Resource(name = "EgovJailbreakDetectionDeviceAPIService")
    private EgovJailbreakDetectionDeviceAPIService egovjailbreakdetectiondeviceAPIService;
    
    /** propertiesService */
    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;
	
    /**
	 * EgovJailbreakDetectionDevice을 위하여 정보를 등록한다.
	 * @param searchVO - 등록할 정보가 담긴JailbreakDetectionDeviceAPIDefaultVO
	 * @param status
	 * @return ModelAndView
	 * @exception Exception
	 */
    @RequestMapping("/jai/addJailbreakDetectionDeviceInfo.do")
    public ModelAndView insertDeviceInfo(
    		@ModelAttribute("searchPushVO") 
    		JailbreakDetectionDeviceAPIVO sampleVO, Model model) 
    throws Exception {
    	
    	ModelAndView jsonView = new ModelAndView("jsonView");
    	
    	int success = egovjailbreakdetectiondeviceAPIService.insertJailbreakDetectionDevcie(sampleVO);
    	if(success > 0) {
			jsonView.addObject("resultState","OK");
			jsonView.addObject("resultMessage","insert success");
		} else {
			jsonView.addObject("resultState","FAIL");
			jsonView.addObject("resultMessage","insert fail");
		}

        return jsonView;
    }
	
    
    /**
	 * EgovJailbreakDetectionDevice 목록을 조회한다.
	 * @param searchVO - 조회할 정보가 담긴JailbreakDetectionDeviceAPIDefaultVO
	 * @param model
	 * @return ModelAndView
	 * @exception Exception
	 */
    @RequestMapping(value="/jai/JailbreakDetectionInfoList.do")
    public ModelAndView selectJailbreakDetectionDevcieList(@ModelAttribute("searchVibratorVO") JailbreakDetectionDeviceAPIDefaultVO searchVO, 
    		ModelMap model)
            throws Exception {
 
		ModelAndView jsonView = new ModelAndView("jsonView");
		List<?> JailbreakDetectionDevcieList = egovjailbreakdetectiondeviceAPIService.selectJailbreakDetectionDevcieList(searchVO);
		
		jsonView.addObject("JailbreakDetectionDevcieList", JailbreakDetectionDevcieList);
		jsonView.addObject("resultState","OK");
		
		return jsonView;
    } 

}
