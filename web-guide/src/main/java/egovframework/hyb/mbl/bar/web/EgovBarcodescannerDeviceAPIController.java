package egovframework.hyb.mbl.bar.web;

import java.util.List;

import javax.annotation.Resource;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import egovframework.hyb.ios.dvc.service.DeviceiOSAPIVO;
import egovframework.hyb.mbl.bar.service.BarcodescannerAPIDefaultVO;
import egovframework.hyb.mbl.bar.service.BarcodescannerAPIVO;
import egovframework.hyb.mbl.bar.service.EgovBarcodescannerAPIService;
import egovframework.rte.fdl.property.EgovPropertyService;
/**
 * @Class Name : EgovBarcodescannerDeviceAPIController
 * @Description : EgovBarcodescannerDeviceAPIController Class
 * @Modification Information
 * @ @ 수정일 수정자 수정내용 @ --------- --------- ------------------------------- @
 *   2016.07.26 신성학 최초 작성
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 06. 20
 * @version 1.0
 * @see
 * 
 * 		Copyright (C) by Ministry of Interior All right reserved.
 */

@Controller
public class EgovBarcodescannerDeviceAPIController {

	/** EgovPushDeviceAPIService */
	@Resource(name = "EgovBarcodescannerAPIService")
	private EgovBarcodescannerAPIService egovBarcodescannerAPIService;

	/** propertiesService */
	@Resource(name = "propertiesService")
	protected EgovPropertyService propertiesService;

	/**
	 * BarcodescannerDevice을 위하여 정보를 등록한다.
	 * 
	 * @param searchVO
	 *            - 등록할 정보가 담긴BarcodescannerDeviceAPIDefaultVO
	 * @param status
	 * @return ModelAndView
	 * @exception Exception
	 */
    @RequestMapping("/bar/addBarcodescannerDeviceInfo.do")
	public ModelAndView insertDeviceInfo(@ModelAttribute("searchPushVO") BarcodescannerAPIVO sampleVO, Model model)
			throws Exception {

		ModelAndView jsonView = new ModelAndView("jsonView");

		int success = egovBarcodescannerAPIService.insertBarcodescannerDevcie(sampleVO);
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
	 * Barcodescanner Device 목록을 조회한다.
	 * 
	 * @param searchVO
	 *            - 조회할 정보가 담긴 PushDeviceAPIDefaultVO
	 * @param model
	 * @return ModelAndView
	 * @exception Exception
	 */
    	@RequestMapping(value = "/bar/BarcodescannerInfoList.do")
	public ModelAndView selectBarcodescannerList(@ModelAttribute("searchVibratorVO") BarcodescannerAPIDefaultVO searchVO,
			ModelMap model) throws Exception {

		ModelAndView jsonView = new ModelAndView("jsonView");

		List<?> BarcodescannerInfoList = egovBarcodescannerAPIService.selectBarcodescannerList(searchVO);
		jsonView.addObject("BarcodescannerInfoList", BarcodescannerInfoList);
		jsonView.addObject("resultState", "OK");

		return jsonView;
	}

}
