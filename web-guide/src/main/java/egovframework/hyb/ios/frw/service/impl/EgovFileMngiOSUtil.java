/**
 * 
 */
package egovframework.hyb.ios.frw.service.impl;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Locale;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import egovframework.com.cmm.security.DeviceAPIFileUploadValidator;
import egovframework.hyb.ios.frw.service.EgovFileReaderWriteriOSAPIService;
import egovframework.hyb.ios.frw.service.FileReaderWriteriOSAPIVO;
import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;
import egovframework.rte.fdl.cmmn.exception.BaseRuntimeException;
import egovframework.rte.fdl.cmmn.exception.FdlException;
import egovframework.rte.fdl.idgnr.EgovIdGnrService;
import egovframework.rte.fdl.property.EgovPropertyService;

/**  
 * @Class Name : EgovFileTransfer.java
 * @Description : EgovFileTransfer
 * @
 * @  수정일         수정자                 수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2012. 7. 10.  서준식                  최초생성
 * @ 2017.02. 27.  최두영        시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754]
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 7. 10.
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */
@Service("egovFileMngiOSUtil")
public class EgovFileMngiOSUtil extends EgovAbstractServiceImpl {
	
	/** Logger */
	private static final Logger LOGGER = LoggerFactory.getLogger(EgovFileMngiOSUtil.class);
	
	/** BUFFER_SIZE */
	private final static int BUFFER_SIZE = 2048;
	
	/** propertiesService */
    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;
	
    /** EgovIdGnrService */
	@Resource(name="egovFileIdGnrService")
	private EgovIdGnrService egovFileIdGnrService;
	
	/** EgovFileReaderWriteriOSAPIService */
	@Resource(name="egovFileReaderWriteriOSAPIService")
	private EgovFileReaderWriteriOSAPIService egovFileReaderWriteriOSAPIService;
	
	
	
	/**
	 * 사용자가 전송한 파일을 업로드 한다.
	 * @param file - 업로드된 파일 정보가 담긴 MultipartFile 
	 * @param fileVO - 파일 정보가 담긴 FileReaderWriteriOSAPIVO 
	 */
	public FileReaderWriteriOSAPIVO writeUploadedFile(MultipartFile file, FileReaderWriteriOSAPIVO fileVO) {

		DeviceAPIFileUploadValidator.validateFrwUpload(file);

		String originFileName = file.getOriginalFilename();
		int index = originFileName.lastIndexOf(".");
		String fileExt = originFileName.substring(index + 1);
		String newName = "File_" + getTimeStamp();
		
		//fileVO에 값 셋팅
		fileVO.setFileStreCours(propertiesService.getString("fileStorePath"));
		fileVO.setOrignlFileNm(originFileName);
		fileVO.setStreFileNm(newName);
		fileVO.setFileExtsn(fileExt);
		fileVO.setFileSize(Long.toString(file.getSize()));
		try {
			fileVO.setFileSn(egovFileIdGnrService.getNextIntegerId());
		} catch (FdlException e) {
			throw new BaseRuntimeException(e);
		}
		
		

		
		if(!file.isEmpty()){
			InputStream input = null;
			FileOutputStream out = null;
			try {
				byte[] bytes = file.getBytes();
				input = new ByteArrayInputStream(bytes);
				
				File videoFile = new File(EgovWebUtil.filePathBlackList(propertiesService.getString("fileStorePath") + newName));
				out = new FileOutputStream(videoFile);
				int nextChar;
				while((nextChar = input.read()) != -1){
					out.write(nextChar);
					out.flush();					
				}
			//2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 113-113
            }catch(IOException e){
            	throw new BaseRuntimeException(e);
			}finally{
				try {
					if(out != null){
						out.close();
					}
				} catch (IOException e) {
					throw new BaseRuntimeException(e);
				}
			}
		}
		
		egovFileReaderWriteriOSAPIService.insertFileDetailInfo(fileVO);
		return fileVO;
	}
	
	/**
	 * 선택된 파일에 대한 다운로드 기능을 처리한다.
	 * @param request - HttpServletRequest 
	 * @param response - HttpServletResponse 
	 * @param fileVO - 파일 정보가 담긴 FileReaderWriteriOSAPIVO 
	 */
	public void fileDownload(HttpServletRequest request, HttpServletResponse response, FileReaderWriteriOSAPIVO fileVO) {
		
		fileDownload(request, response, fileVO.getOrignlFileNm(), fileVO.getStreFileNm());
		
	}
	
	/**
	 * 선택된 파일에 대한 다운로드 기능을 처리한다.
	 * @param request - HttpServletRequest 
	 * @param response - HttpServletResponse 
	 * @param fileVO - 파일 정보가 담긴 FileReaderWriteriOSAPIVO 
	 */
	public String computeFileSha256(String streFileNm) {
		File file = new File(EgovWebUtil.filePathBlackList(propertiesService.getString("fileStorePath") + streFileNm));
		if (!file.exists() || !file.isFile()) {
			throw new BaseRuntimeException(streFileNm);
		}

		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new BaseRuntimeException(e);
		}
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(file);
			byte[] buffer = new byte[BUFFER_SIZE];
			int read;
			while ((read = fis.read(buffer)) != -1) {
				digest.update(buffer, 0, read);
			}
		} catch (IOException e) {
			throw new BaseRuntimeException(e);
		} finally {
			if (fis != null) {
				try {
					fis.close();
				} catch (IOException e) {
					throw new BaseRuntimeException(e);
				}
			}
		}

		byte[] hash = digest.digest();
		StringBuilder sb = new StringBuilder(hash.length * 2);
		for (byte b : hash) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

	public void fileDownload(HttpServletRequest request, HttpServletResponse response, String originalFileName, String streFileNm) {
		DeviceAPIFileUploadValidator.assertSafeStoredFileName(streFileNm);
		File file = new File(EgovWebUtil.filePathBlackList(propertiesService.getString("fileStorePath") + streFileNm));
		
		if(!file.exists()){
			throw new BaseRuntimeException(streFileNm);
		}
		if(!file.isFile()){
			throw new BaseRuntimeException(streFileNm);
		}
		
		
		byte[] buffer = new byte[BUFFER_SIZE];
		
		
		response.setContentType("video/quicktime");
		try {
			response.setHeader("Content-Disposition:", "attachment; filename=" + new String(originalFileName.getBytes(), "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			throw new BaseRuntimeException(e);
		}
		response.setHeader("Content-Transfer-Encoding", "binary");
		response.setHeader("Content-Length", ""+file.length());
		response.setHeader("Pragma", "no-cache");
		response.setHeader("Expires", "0");
		
		BufferedInputStream fin = null;
		BufferedOutputStream outs = null;

		try {
			fin = new BufferedInputStream(new FileInputStream(file));
		    outs = new BufferedOutputStream(response.getOutputStream());
		    int read = 0;

			while ((read = fin.read(buffer)) != -1) {
			    outs.write(buffer, 0, read);
			}
		} catch (IOException e) {
			throw new BaseRuntimeException(e);
		} finally {
			if (outs != null) {
				try {
					outs.close();
				//2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 188-188
				}catch (IOException e){
					throw new BaseRuntimeException(e);
				}
			}
			if (fin != null) {
				try {
					fin.close();
				//2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 195-195
				}catch (IOException e){
					throw new BaseRuntimeException(e);
				}
			}
		}

	}
	
	
	/**
	 * 선택된 파일에 대한 삭제 기능을 처리한다.
	 * @param fileVO - 파일 정보가 담긴 FileReaderWriteriOSAPIVO 
	 */
	public void deleteFile(FileReaderWriteriOSAPIVO fileVO) {
		
		File videoFile = new File(EgovWebUtil.filePathBlackList(propertiesService.getString("fileStorePath") + fileVO.getStreFileNm()));
		
		if(!videoFile.exists()){
			LOGGER.info("There is no file to remove.");			
		}
		if(!videoFile.isFile()){
			LOGGER.info("This is not file.");
		}
		
		boolean result = false;
		
		if(videoFile != null){
			result = videoFile.delete();
		}
		
		
		if(result == false){
			LOGGER.info("Fail to remove file.");
		}
			
		
		egovFileReaderWriteriOSAPIService.deleteFileDetailInfo(fileVO);
	
		
		
		
		
	}
	
	
	
	
	
	
	/**
	 * yyyyMMddhhmmssSSS 패턴의 현재 날자를 반환한다.
	 * @return String
	 */
	private static String getTimeStamp(){
		String rtnStr = null;

		// 문자열로 변환하기 위한 패턴 설정(년도-월-일 시:분:초:초(자정이후 초))
		String pattern = "yyyyMMddhhmmssSSS";

	    SimpleDateFormat sdfCurrent = new SimpleDateFormat(pattern, Locale.KOREA);
	    Timestamp ts = new Timestamp(System.currentTimeMillis());

	    rtnStr = sdfCurrent.format(ts.getTime());

		return rtnStr;
	}
}
