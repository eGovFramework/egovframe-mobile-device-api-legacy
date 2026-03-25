package egovframework.hyb.ios.mda.service.impl;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Locale;

import egovframework.hyb.ios.mda.service.EgovMediaiOSAPIService;
import egovframework.hyb.ios.mda.service.MediaiOSAPIFileVO;

import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;
import egovframework.rte.fdl.cmmn.exception.EgovBizException;
import egovframework.rte.fdl.idgnr.EgovIdGnrService;
import egovframework.rte.fdl.property.EgovPropertyService;

import javax.annotation.Resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

/**  
 * @Class Name : EgovFileTransfer.java
 * @Description : EgovFileTransfer
 * @
 * @  수정일         수정자                 수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2012. 7. 10.  서준식                  최초생성
 * @ 2012. 7. 30.  이율경                  커스터마이징
 * @ 2012. 8. 14.  이해성                  커스터마이징
 * @ 2017.02. 27.  최두영        시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754]
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 7. 10.
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */
@Service("EgovMediaiOSFileMngUtil")
public class EgovMediaiOSFileMngUtil extends EgovAbstractServiceImpl {
	
	/** EgovCameraiOSAPIService */
    @Resource(name = "EgovMediaiOSAPIService")
    private EgovMediaiOSAPIService egovMediaiOSAPIService;

    private static final Logger LOGGER = LoggerFactory.getLogger(EgovMediaiOSFileMngUtil.class);
	
	/** propertiesService */
    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;
	
	@Resource(name="egovFileIdGnrService")
	private EgovIdGnrService egovFileIdGnrService;
	
	
	public MediaiOSAPIFileVO writeUploadedFile(MultipartFile file) throws Exception{
		
		String originFileName = file.getOriginalFilename();
		int index = originFileName.lastIndexOf(".");
		String fileExt = originFileName.substring(index + 1);
		String newName = "RECORD_" + getTimeStamp() + ".wav";
		
		// 파일 경로 바꾸어야함.
		String filePath = propertiesService.getString("fileStorePath");
		
		MediaiOSAPIFileVO fileVO = new MediaiOSAPIFileVO();
		
		fileVO.setFileSn(egovFileIdGnrService.getNextIntegerId());
		fileVO.setFileStreCours(filePath);
		fileVO.setStreFileNm(newName);
		fileVO.setOrignlFileNm(originFileName);
		fileVO.setFileExtsn(fileExt);
		fileVO.setFileSize(Long.toString(file.getSize()));
		
		if(!file.isEmpty()){
			InputStream input = null;
			FileOutputStream out = null;
			try {
				byte[] bytes = file.getBytes();
				input = new ByteArrayInputStream(bytes);
				
				// 260320 KISA 보안취약점 패치
				File videoFile = new File(EgovWebUtil.filePathBlackList(filePath + newName));
				out = new FileOutputStream(videoFile);
				int nextChar;
				while((nextChar = input.read()) != -1){
					out.write(nextChar);
					out.flush();
					
				}
			//2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 95-95
			}catch(NullPointerException e){
				LOGGER.error("[NullPointerException] Try/Catch...NullPointerException : " + e.getMessage());
				throw new EgovBizException("Fail to create file : " + e.getMessage());
			}catch(FileNotFoundException e){
				LOGGER.error("[FileNotFoundException] Try/Catch...FileNotFoundException : " + e.getMessage());
				throw new EgovBizException("Fail to find file : " + e.getMessage());
			}catch (Exception e) {
				LOGGER.error("["+e.getClass()+"] Try/Catch... : " + e.getMessage());
				throw new EgovBizException("Fail to upload file : " + e.getMessage());
			}finally{
				try {
					if(out != null){
						out.close();
					}
					
				} catch (IOException e) {
					LOGGER.debug("Fail to close fileoutputstrem : {}", e.getMessage());
					
				}
			}
		}
		egovMediaiOSAPIService.insertMediaRecordFile(fileVO);
		
		return fileVO;
	}
	
	private static String getTimeStamp(){
		String rtnStr = null;

		// 문자열로 변환하기 위한 패턴 설정(년도-월-일 시:분:초:초(자정이후 초))
		String pattern = "yyyyMMddhhmmssSSS";

		try {
		    SimpleDateFormat sdfCurrent = new SimpleDateFormat(pattern, Locale.KOREA);
		    Timestamp ts = new Timestamp(System.currentTimeMillis());

		    rtnStr = sdfCurrent.format(ts.getTime());
		//2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 126-126
		} catch(NullPointerException e){
			LOGGER.error("[NullPointerException] Try/Catch... : " + e.getMessage());
		} catch (Exception e) {
		    //e.printStackTrace();			
		    //throw new RuntimeException(e);	// 보안점검 후속조치
			LOGGER.error("["+e.getClass()+"] Try/Catch... : " + e.getMessage());
		}

		return rtnStr;
	}
}
