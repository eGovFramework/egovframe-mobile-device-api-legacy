package egovframework.hyb.add.frw.web;

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

import egovframework.hyb.add.frw.service.EgovFileReaderWriterAndroidAPIService;
import egovframework.hyb.add.frw.service.FileReaderWriterAndroidAPIVO;
import egovframework.hyb.add.frw.service.FileReaderWriterAndroidAPIVOList;
import egovframework.com.cmm.security.DeviceAPIAuthSupport;
import egovframework.hyb.add.frw.service.impl.EgovFileMngAndroidUtil;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;

/**  
 * @Class Name : EgovFileReaderWriterAndroidAPIController.java
 * @Description : EgovFileReaderWriterAndroidAPIController
 * @
 * @ 수정일         수정자        수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.08.06   나신일        최초생성
 *   2020.08.24   신용호        Swagger 적용
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 8. 6
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */
@Controller
public class EgovFileReaderWriterAndroidAPIController {

	/** EgovFileReaderWriterAndroidAPIService */
	@Resource(name = "egovFileReaderWriterAndroidAPIService")
	private EgovFileReaderWriterAndroidAPIService egovFileReaderWriterAndroidAPIService;

	/** egovFileMngAndroidUtil */
	@Resource(name = "egovFileMngAndroidUtil")
	private EgovFileMngAndroidUtil egovFileMngAndroidUtil;

	/**
	 * 파일 정보 목록을 조회한다.
	 * 
	 * @param fileVO
	 *            - 조회할 정보가 담긴 FileReaderWriterAndroidAPIVO
	 * @return FileReaderWriterAndroidAPIVOList
	 * @exception Exception
	 */
    @ApiOperation(value="파일 정보 목록조회", notes="[Android] 파일 정보 목록을 조회한다.", response=FileReaderWriterAndroidAPIVO.class, responseContainer="List")
    @ApiImplicitParams({
    	@ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
    })
	@SuppressWarnings("unchecked")
	@RequestMapping("/frw/xml/fileInfoList.do")
	public @ResponseBody
	FileReaderWriterAndroidAPIVOList selectFileInfoListXml(FileReaderWriterAndroidAPIVO fileVO) throws Exception {

		List<FileReaderWriterAndroidAPIVO> fileInfoList = (List<FileReaderWriterAndroidAPIVO>) egovFileReaderWriterAndroidAPIService.selectFileInfoList(fileVO);

		FileReaderWriterAndroidAPIVOList fileReaderWriterAndroidAPIVOList = new FileReaderWriterAndroidAPIVOList();

		fileReaderWriterAndroidAPIVOList.setFileInfoList(fileInfoList);

		return fileReaderWriterAndroidAPIVOList;
	}

	/**
	 * 파일 정보 삭제를 요청 한다.
	 * 
	 * @param fileVO
	 *            - 삭제할 정보가 담긴 FileReaderWriterAndroidAPIVO
	 * @return FileReaderWriterAndroidAPIVO
	 * @exception Exception
	 */
    @ApiOperation(value="파일 정보 삭제", notes="[Android] 파일 정보를 삭제한다.responseOK = {\"resultState\",\"OK\"}")
    @ApiImplicitParams({
    	@ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
    	@ApiImplicitParam(name = "fileSn", value = "파일연번", required = true, dataType = "int", paramType = "query"),
    })
	@RequestMapping("/frw/xml/deleteFile.do")
	public @ResponseBody
	FileReaderWriterAndroidAPIVO deleteFile(FileReaderWriterAndroidAPIVO fileVO, HttpServletRequest request) throws Exception {

		FileReaderWriterAndroidAPIVO fileReaderWriterAndroidAPIVO = new FileReaderWriterAndroidAPIVO();

		fileVO.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, fileVO.getUuid()));
		FileReaderWriterAndroidAPIVO selectInfoVO = egovFileReaderWriterAndroidAPIService.selectFileInfo(fileVO);

		if (selectInfoVO == null) {
			fileReaderWriterAndroidAPIVO.setResultState("FAIL");
			fileReaderWriterAndroidAPIVO.setResultMessage("삭제 권한이 없거나 파일을 찾을 수 없습니다.");
			return fileReaderWriterAndroidAPIVO;
		}

		if (egovFileMngAndroidUtil.deleteFile(selectInfoVO)) {

			egovFileReaderWriterAndroidAPIService.deleteFileDetailInfo(selectInfoVO);

			fileReaderWriterAndroidAPIVO.setResultState("OK");
			fileReaderWriterAndroidAPIVO.setResultMessage("삭제에 성공하였습니다.");

		} else {
			fileReaderWriterAndroidAPIVO.setResultState("FAIL");
			fileReaderWriterAndroidAPIVO.setResultMessage("삭제에 실패하였습니다.");
		}

		return fileReaderWriterAndroidAPIVO;
	}

	/**
	 * 서버로 전송된 파일을 저장한다.
	 * 
	 * @param file
	 *            - MultipartFile
	 * @param fileVO
	 *            - 저장할 정보가 담긴 FileReaderWriterAndroidAPIVO
	 * @return ModelAndView
	 * @exception Exception
	 */
    @ApiOperation(value="파일 서버로 전송하여 등록", notes="[Android] 파일 서버로 전송하여 등록한다.\nresponseOK = \"ok\"")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "file", value = "이미지파일", required = true, dataType = "__file", paramType = "form"),
    })
	@RequestMapping(value="/frw/xml/fileUpload.do", method=RequestMethod.POST)
	public @ResponseBody
	String fileUpload(@RequestParam("file") MultipartFile file, FileReaderWriterAndroidAPIVO fileVO, HttpServletRequest request) throws Exception {

		String result = "";
		if (!file.isEmpty()) {

			FileReaderWriterAndroidAPIVO writeVO = egovFileMngAndroidUtil.writeUploadedFile(file, fileVO);

			writeVO.setFileNm(file.getOriginalFilename());
			writeVO.setFileType("MEDIA");
			writeVO.setUseYn("Y");

			egovFileReaderWriterAndroidAPIService.insertFileInfo(writeVO);

			result = "ok";

			return result.toString();
		} else {
			result = "fail";
			return result.toString();
		}
	}

	/**
	 * 선택된 파일을 클라이언트로 전송한다.
	 * 
	 * @param request
	 *            - HttpServletRequest
	 * @param response
	 *            - HttpServletResponse
	 * @param fileVO
	 *            - 전송할 파일 정보가 담긴 FileReaderWriterAndroidAPIVO
	 * @return ModelAndView
	 * @exception Exception
	 */
    @ApiOperation(value="파일 다운로드", notes="[Android] 파일 다운로드 한다.")
    @ApiImplicitParams({
    	@ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
    	@ApiImplicitParam(name = "fileSn", value = "파일연번", required = true, dataType = "int", paramType = "query"),
    })
	@RequestMapping("/frw/xml/fileDownload.do")
	public void fileDownload(HttpServletRequest request, HttpServletResponse response, FileReaderWriterAndroidAPIVO fileVO) throws Exception {

		fileVO.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, fileVO.getUuid()));
		FileReaderWriterAndroidAPIVO selectInfoVO = egovFileReaderWriterAndroidAPIService.selectFileInfo(fileVO);
		if (selectInfoVO == null) {
			response.sendError(HttpServletResponse.SC_FORBIDDEN, "File access denied.");
			return;
		}
		egovFileMngAndroidUtil.fileDownload(request, response, selectInfoVO);
	}

}
