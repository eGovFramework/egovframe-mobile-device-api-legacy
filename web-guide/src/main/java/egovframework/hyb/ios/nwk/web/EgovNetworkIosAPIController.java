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
package egovframework.hyb.ios.nwk.web;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.List;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import egovframework.hyb.add.nwk.service.NetworkAndroidAPIXmlVO;
import egovframework.hyb.ios.nwk.service.EgovNetworkiOSAPIService;
import egovframework.hyb.ios.nwk.service.NetworkiOSAPIDefaultVO;
import egovframework.hyb.ios.nwk.service.NetworkiOSAPIVO;
import egovframework.rte.fdl.property.EgovPropertyService;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;

/**  
 * @Class Name : EgovNetworkAPIController
 * @Description : EgovNetworkAPI Controller Class
 * @Modification Information  
 * @
 * @ 수정일              수정자               수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.06.18   서준식              최초 작성
 *   2012.08.01   이해성              DeviceAPIGuide Network Info
 *   2017.02.27   최두영              시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754]
 *   2019.10.14   신용호              iOS에서 확장자를 mp3로 인식하도록 contentDisposition값을 설정(getMp3File)
 *   2020.09.07   신용호              Swagger 적용
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 06. 18
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

@Controller
public class EgovNetworkIosAPIController {
	
	/** EgovNetworkiOSAPIService */
    @Resource(name = "EgovNetworkiOSAPIService")
    private EgovNetworkiOSAPIService egovNetworkiOSAPIService;
    
    /** propertiesService */
    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;
 
    private static final Logger LOGGER = LoggerFactory.getLogger(EgovNetworkIosAPIController.class);
    
    /**
	 * 어플리케이션 실행 시, 서버 설정
	 * @return boolean
	 * @exception Exception
	 */
    @RequestMapping("/nwk/htmlLoadiOS.do")
    public ModelAndView htmlLoad(ModelMap model)
            throws Exception {
		ModelAndView jsonView = new ModelAndView("jsonView");
		
		jsonView.addObject("serverUrl", propertiesService.getString("serverContext"));
		jsonView.addObject("resultState","OK");
		
		return jsonView;
    }
    
    /**
	 * 네트워크 정보 목록을 조회한다.
	 * @param searchVO - 조회할 정보가 담긴 NetworkAPIDefaultVO
	 * @param model
	 * @return ModelAndView
	 * @exception Exception
	 */
    @ApiOperation(value="Network 정보 목록조회", notes="[iOS] Network 정보 목록을 조회한다.", response=NetworkAndroidAPIXmlVO.class, responseContainer="List")
    @RequestMapping(value="/nwk/networkiOSInfoList.do")
    public ModelAndView selectNetworkInfoList(@ModelAttribute("searchNetworkiOSVO") NetworkiOSAPIDefaultVO searchNetworkVO,
    		NetworkiOSAPIVO sampleNetworkVO,
    		ModelMap model)
            throws Exception {
 
		ModelAndView jsonView = new ModelAndView("jsonView");
		List<?> networkInfoList = egovNetworkiOSAPIService.selectNetworkInfoList(sampleNetworkVO);
		
		jsonView.addObject("networkInfoList", networkInfoList);
		jsonView.addObject("resultState","OK");
		
		return jsonView;
    }
    
    /**
	 * 네트워크 정보를 조회한다.
	 * @param searchVO - 조회할 정보가 담긴 NetworkAPIDefaultVO
	 * @param model
	 * @return ModelAndView
	 * @exception Exception
	 */
    @ApiOperation(value="Network 세부정보 조회", notes="[iOS] Network 세부정보를 조회한다.", response=NetworkiOSAPIVO.class)
    @ApiImplicitParams({
        @ApiImplicitParam(name = "sn", value = "일련번호", required = true, dataType = "int", paramType = "query"),
    })
    @RequestMapping(value="/nwk/networkiOSInfo.do")
    public ModelAndView selectNetworkInfo(
    		NetworkiOSAPIVO sampleNetworkVO,
            BindingResult bindingResult, Model model, SessionStatus status)
            throws Exception {
 
		ModelAndView jsonView = new ModelAndView("jsonView");
		NetworkiOSAPIVO networkInfo = egovNetworkiOSAPIService.selectNetworkInfo(sampleNetworkVO);
		
		jsonView.addObject("networkInfo", networkInfo);
		jsonView.addObject("resultState","OK");
		
		return jsonView;
    }
    
    /**
	 * 네트워크 정보를 등록한다.
	 * @param searchVO - 등록할 정보가 담긴 NetworkAPIDefaultVO
	 * @param status
	 * @return ModelAndView
	 * @exception Exception
	 */
    @ApiOperation(value="Network 세부정보 등록", notes="[iOS] Network 세부정보를 등록한다.\nresponseOK = {\"resultState\",\"OK\"}")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "sn", value = "일련번호", required = true, dataType = "int", paramType = "query"),
    })
    @RequestMapping("/nwk/addNetworkiOSInfo.do")
    public ModelAndView insertNetworkInfo(
       	 	NetworkiOSAPIVO sampleNetworkVO,
            BindingResult bindingResult, Model model, SessionStatus status) 
    throws Exception {
    	
    	/*if (bindingResult.hasErrors()) {
    		model.addAttribute("sampleVO", sampleVO);
			return "/sample/egovSampleRegister";
    	}*/
    	
    	ModelAndView jsonView = new ModelAndView("jsonView");
    	
    	int success = egovNetworkiOSAPIService.insertNetworkInfo(sampleNetworkVO);
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
	 * 네트워크 정보 목록을 삭제한다.
	 * @param sampleVO - 삭제할 정보가 담긴 VO
	 * @param status
	 * @return ModelAndView
	 * @exception Exception
	 */
    @ApiOperation(value="Network 세부정보 삭제", notes="[iOS] Network 세부정보를 삭제한다.\nresponseOK = {\"resultState\",\"OK\"}")
    @ApiImplicitParams({
    	@ApiImplicitParam(name = "sn", value = "일련번호", required = true, dataType = "int", paramType = "query"),
    })
    @RequestMapping("/nwk/deleteNetworkiOSInfo.do")
    public ModelAndView deleteNetworkInfo(
            NetworkiOSAPIVO sampleVO, SessionStatus status)
            throws Exception {
    	
        ModelAndView jsonView = new ModelAndView("jsonView");
        
    	int success = egovNetworkiOSAPIService.deleteNetworkInfo(sampleVO);
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
	 * 재생할 mp3 파일을 리턴한다
	 * @param sampleVO - 삭제할 정보가 담긴 VO
	 * @param status
	 * @return ModelAndView
	 * @exception Exception
	 */
    @ApiOperation(value="Network MP3파일 다운로드", notes="[iOS] MP3파일을 다운로드 받는다.\nglobals.properties설정파일에 \"fileStorePath\"로 정의한 설정경로에서 \"owlband.mp3\"파일을 다운로드 한다.")
    @RequestMapping("/nwk/getMp3FileiOS.do")
    public void getMp3File( HttpServletResponse response) throws Exception {
    	
    	String mp3FilePath = propertiesService.getString("fileStorePath");
    	File file = null;
		FileInputStream fis = null;
	
		BufferedInputStream in = null;
		ByteArrayOutputStream bStream = null;
		
		String filename = "owlband.mp3";
		String charSet = "UTF-8";
		//String contentDisposition = "attachment; filename*="+charSet+"''"+URLEncoder.encode(filename, charSet);
		
		try {
		    
		    file = new File(mp3FilePath + filename);
		    fis = new FileInputStream(file);
	
		    in = new BufferedInputStream(fis);
		    bStream = new ByteArrayOutputStream();
	
		    int imgByte;
		    while ((imgByte = in.read()) != -1) {
		    	bStream.write(imgByte);
		    }
	
			response.setHeader("Content-Type", "audio/mp3");
			response.setContentLength(bStream.size());
			//response.setHeader("Content-Disposition", contentDisposition);
		
			bStream.writeTo(response.getOutputStream());
		
			response.getOutputStream().flush();
			response.getOutputStream().close();
		//2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 236-236
		}catch(NullPointerException e){
			LOGGER.error("[NullPointerException e] Try/Catch...NullPointerException e : " + e.getMessage());
		}catch(FileNotFoundException e){
			LOGGER.error("[FileNotFoundException] Try/Catch...FileNotFoundException : " + e.getMessage());
		}catch(Exception e) {
			LOGGER.error("["+e.getClass()+"] Try/Catch... : " + e.getMessage());
		} finally {
			if (bStream != null) {
				try {
					bStream.close();
				//2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 242-242	
				}catch(IOException e){
					LOGGER.error("[IOException] Try/Catch... : " + e.getMessage());
				}catch (Exception e) {
					LOGGER.error("["+e.getClass()+"] Try/Catch... : " + e.getMessage());
				}
			}
			if (in != null) {
				try {
					in.close();
				//2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 249-249	
				}catch(IOException e){
					LOGGER.error("[IOException] Try/Catch... : " + e.getMessage());
				}catch (Exception e) {
					LOGGER.error("["+e.getClass()+"] Try/Catch... : " + e.getMessage());
				}
			}
			if (fis != null) {
				try {
					fis.close();
				//2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 256-256	
				}catch(IOException e){
					LOGGER.error("[IOException] Try/Catch... : " + e.getMessage());
				}catch (Exception e) {
					LOGGER.error("["+e.getClass()+"] Try/Catch... : " + e.getMessage());
				}
			}
		}
    }
}
