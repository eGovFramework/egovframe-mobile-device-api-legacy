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
package egovframework.hyb.ios.mda.web;

import java.util.List;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.multipart.MultipartFile;

import egovframework.hyb.ios.mda.service.EgovMediaiOSAPIService;
import egovframework.hyb.ios.mda.service.MediaiOSAPIFileVO;
import egovframework.hyb.ios.mda.service.MediaiOSAPIVO;
import egovframework.hyb.ios.mda.service.MediaiOSAPIXmlVO;
import egovframework.hyb.ios.mda.service.impl.EgovMediaiOSFileMngUtil;
import egovframework.rte.fdl.property.EgovPropertyService;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;

/**  
 * @Class Name : EgovMediaiOSAPIController.java
 * @Description : EgovMediaiOSAPIController Class
 * @Modification Information  
 * @
 * @ 수정일         수정자             수정내용
 * @ ----------	  ---------------	-------------------------------
 *   2012.07.30	  이율경              최초생성
 *   2012.08.14	  이해성              커스터마이징
 *   2020.09.07   신용호              Swagger 적용
 * 
 * @author 디바이스 API 실행환경 팀
 * @since 2012. 7. 30.
 * @version 1.0
 * @see
 * 
 */
@Controller
public class EgovMediaIosAPIController {

	/** EgovMediaiOSAPIService */
    @Resource(name = "EgovMediaiOSAPIService")
    private EgovMediaiOSAPIService egovMediaiOSAPIService;
	
    /** propertiesService */
    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;
    
    /** EgovFileMngUtil */
    @Resource(name = "EgovMediaiOSFileMngUtil")
	private EgovMediaiOSFileMngUtil egovMediaiOSFileMngUtil;
    
    /**
	 * 어플리케이션 실행 시, 서버 설정
	 * @return boolean
	 * @exception Exception
	 */
    @RequestMapping("/mda/htmlLoadiOS.do")
	public @ResponseBody MediaiOSAPIXmlVO htmlLoad(SessionStatus status) 
    throws Exception{
		
    	MediaiOSAPIXmlVO mediaiOSAPIXmlVO = new MediaiOSAPIXmlVO();
    	
    	mediaiOSAPIXmlVO.setResultState("OK");
    	mediaiOSAPIXmlVO.setServerContext(propertiesService.getString("serverContext"));
    	mediaiOSAPIXmlVO.setDownloadContext(propertiesService.getString("downloadContext"));
    	
    	return mediaiOSAPIXmlVO;
	}
    
    /**
	 * 녹음 파일을 등록한다. (업로드)
	 * @param file - 녹음 파일 정보가 담긴 MultipartFile
	 * @param fileVO - 등록 정보가 담긴 CameraiOSAPIVO
	 * @return boolean
	 * @exception Exception
	 */
    @RequestMapping("/mda/mediaiOSRecordUpload.do")
	public @ResponseBody boolean fileUpload(@RequestParam("file") MultipartFile file, MediaiOSAPIVO vo, 
			HttpServletRequest request) throws Exception{
		
		if (!file.isEmpty()) {
			
			MediaiOSAPIFileVO fileVO = egovMediaiOSFileMngUtil.writeUploadedFile(file);
			
			egovMediaiOSAPIService.insertMediaInfo(vo, fileVO.getFileSn());
			
			return true;
		} else {
			
			return false;
		}
	}
    
    /**
	 * 미디어 정보를 조회한다.
	 * @param VO - 조회할 정보가 담긴 MediaiOSAPIVO
	 * @return 조회 목록
	 * @exception Exception
	 */
    @ApiOperation(value="Media 세부정보 조회", notes="[iOS] Media 세부정보를 조회한다.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "sn", value = "일련번호", required = true, dataType = "int", paramType = "query"),
    })
    @RequestMapping("/mda/mediaiOSInfoDetail.do")
	public @ResponseBody MediaiOSAPIXmlVO selectMediaInfoDetail(MediaiOSAPIVO vo) throws Exception {
		
    	MediaiOSAPIFileVO mediaInfo = egovMediaiOSAPIService.selectMediaInfoDetail(vo);
    	
    	MediaiOSAPIXmlVO mediaiOSAPIXmlVO = new MediaiOSAPIXmlVO();
    	mediaiOSAPIXmlVO.setResultState("OK");
    	mediaiOSAPIXmlVO.setMediaiOSAPIFileVO(mediaInfo);
    	
    	return mediaiOSAPIXmlVO;
	}
    
    /**
	 * 미디어 목록을 조회한다.
	 * @param VO - 조회할 정보가 담긴 MediaiOSAPIVO
	 * @return 조회 목록
	 * @exception Exception
	 */
    @ApiOperation(value="Media 정보 목록조회", notes="[iOS] Media 정보 목록을 조회한다.")
    @ApiImplicitParams({
    	@ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
    })
    @SuppressWarnings("unchecked")
	@RequestMapping("/mda/mediaiOSInfoList.do")
	public @ResponseBody MediaiOSAPIXmlVO selectMediaInfoList(MediaiOSAPIVO vo) throws Exception {
		
    	List<MediaiOSAPIVO> mediaList = (List<MediaiOSAPIVO>) egovMediaiOSAPIService.selectMediaInfoList(vo);
    	
    	MediaiOSAPIXmlVO mediaiOSAPIXmlVO = new MediaiOSAPIXmlVO();
    	mediaiOSAPIXmlVO.setResultState("OK");
    	mediaiOSAPIXmlVO.setMediaiOSAPIVOList(mediaList);
    	
    	return mediaiOSAPIXmlVO;
	}
    
    /**
	 * 미디어 파일을 조회한다.
	 * @param fileVO - 조회할 정보가 담긴 CameraiOSAPIFileVO
	 * @param model
	 * @param response
	 * @return jsonView
	 * @exception Exception
	 */
    @ApiOperation(value="Media 파일 다운로드", notes="[iOS] Media 파일을 다운로드 한다.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "sn", value = "일련번호", required = true, dataType = "int", paramType = "query"),
    })
    @RequestMapping("/mda/getMediaiOS.do")
    public void getSoundFile(@RequestParam("sn") String sn, HttpServletRequest request, HttpServletResponse response) throws Exception {
    	if(sn != null && "".equals(sn) == false) {
    		MediaiOSAPIFileVO vo = new MediaiOSAPIFileVO();
			vo.setSn(Integer.parseInt(sn));
		
			egovMediaiOSAPIService.selectMediaFileInf(response, vo);
    	}
    }
}
