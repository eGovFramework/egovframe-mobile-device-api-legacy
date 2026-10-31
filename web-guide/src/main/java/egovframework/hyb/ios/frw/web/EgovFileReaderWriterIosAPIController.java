package egovframework.hyb.ios.frw.web;

import java.util.List;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;

import egovframework.com.cmm.security.DeviceAPIAuthSupport;
import egovframework.hyb.ios.frw.service.EgovFileReaderWriteriOSAPIService;
import egovframework.hyb.ios.frw.service.FileReaderWriteriOSAPIVO;
import egovframework.hyb.ios.frw.service.impl.EgovFileMngiOSUtil;
/**  
 * @Class Name : EgovFileReaderWriteriOSAPIController.java
 * @Description : EgovFileReaderWriteriOSAPIController
 * @
 * @ 수정일         수정자        수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.07.10   서준식        최초생성
 *   2020.08.24   신용호        Swagger 적용
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 7. 10.
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */
@Controller
public class EgovFileReaderWriterIosAPIController {
	
	/** EgovFileReaderWriteriOSAPIService */
	@Resource(name="egovFileReaderWriteriOSAPIService")
	private EgovFileReaderWriteriOSAPIService egovFileReaderWriteriOSAPIService;

	/** EgovFileMngUtil */
	@Resource(name = "egovFileMngiOSUtil")
	private EgovFileMngiOSUtil egovFileMngUtil;
	
	
	/**
	 * 파일  정보 목록을 조회한다.
	 * @param fileVO - 조회할 정보가 담긴 FileReaderWriteriOSAPIVO 
	 * @return ModelAndView
	 * @exception Exception
	 */
    @RequestMapping("/frw/fileInfoList.do")
	public ModelAndView selectFileInfoList(FileReaderWriteriOSAPIVO fileVO) throws Exception{
		ModelAndView jsonView = new ModelAndView("jsonView");
		List<?> fileInfoList = egovFileReaderWriteriOSAPIService.selectFileInfoList(fileVO);
		
		jsonView.addObject("fileInfoList", fileInfoList);
		jsonView.addObject("resultStatus","OK");
		
		return jsonView;
	}
	
	/**
	 * 파일  정보  삭제를 요청 한다.
	 * @param fileVO - 삭제할 정보가 담긴 FileReaderWriteriOSAPIVO 
	 * @return ModelAndView
	 * @exception Exception
	 */
    @RequestMapping("/frw/deleteFile.do")
	public ModelAndView deleteFile(FileReaderWriteriOSAPIVO fileVO, HttpServletRequest request) throws Exception{

		fileVO.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, fileVO.getUuid()));
		FileReaderWriteriOSAPIVO fileReaderWriteriOSAPIVO = egovFileReaderWriteriOSAPIService.selectFileInfo(fileVO);
		if (fileReaderWriteriOSAPIVO == null) {
			ModelAndView deniedView = new ModelAndView("jsonView");
			deniedView.addObject("resultStatus", "FAIL");
			deniedView.addObject("resultMessage", "삭제 권한이 없거나 파일을 찾을 수 없습니다.");
			return deniedView;
		}

		egovFileReaderWriteriOSAPIService.deleteFileInfo(fileReaderWriteriOSAPIVO);
		egovFileMngUtil.deleteFile(fileReaderWriteriOSAPIVO);
		
		
		ModelAndView jsonView = new ModelAndView("jsonView");
		jsonView.addObject("resultStatus","OK");
		
		return jsonView;
	}
	
	
	/**
	 * 서버로 전송된 파일을 저장한다.
	 * @param file -  MultipartFile 
	 * @param fileVO - 저장할 정보가 담긴 FileReaderWriteriOSAPIVO 
	 * @return ModelAndView
	 * @exception Exception
	 */
    @RequestMapping(value="/frw/fileUpload.do", method=RequestMethod.POST)
	public @ResponseBody String fileUpload(@RequestParam("file") MultipartFile file, FileReaderWriteriOSAPIVO fileVO, HttpServletRequest request) throws Exception{
		
		String result = "";
		if (!file.isEmpty()) {
			
			FileReaderWriteriOSAPIVO fileReaderWriteriOSAPIVO = egovFileMngUtil.writeUploadedFile(file, fileVO);
			
			fileReaderWriteriOSAPIVO.setFileNm(file.getOriginalFilename());
			fileReaderWriteriOSAPIVO.setFileType("MEDIA");
			fileReaderWriteriOSAPIVO.setUseYn("Y");
			
			egovFileReaderWriteriOSAPIService.insertFileInfo(fileReaderWriteriOSAPIVO);
			
			result = "ok";
			
			return result.toString();
		} else {
			result = "fail";
			return result.toString();
		}
	}
	
	/**
	 * 선택된 파일을 클라이언트로 전송한다.
	 * @param request -  HttpServletRequest 
	 * @param response - HttpServletResponse 
	 * @param fileVO - 전송할 파일 정보가 담긴 FileReaderWriteriOSAPIVO 
	 * @return ModelAndView
	 * @exception Exception
	 */
    @RequestMapping("/frw/fileDownload.do")
	public void fileDownload(HttpServletRequest request, HttpServletResponse response, FileReaderWriteriOSAPIVO fileVO) throws Exception{

		fileVO.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, fileVO.getUuid()));
		FileReaderWriteriOSAPIVO fileReaderWriteriOSAPIVO = egovFileReaderWriteriOSAPIService.selectFileInfo(fileVO);
		if (fileReaderWriteriOSAPIVO == null) {
			response.sendError(HttpServletResponse.SC_FORBIDDEN, "File access denied.");
			return;
		}
		egovFileMngUtil.fileDownload(request, response, fileReaderWriteriOSAPIVO);
	}
	
}

