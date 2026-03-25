package egovframework.hyb.add.mda.service.impl;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Locale;

import egovframework.hyb.add.mda.service.EgovMediaAndroidAPIService;
import egovframework.hyb.add.mda.service.MediaAndroidAPIFileVO;

import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;
import egovframework.rte.fdl.cmmn.exception.EgovBizException;
import egovframework.rte.fdl.idgnr.EgovIdGnrService;
import egovframework.rte.fdl.property.EgovPropertyService;

import javax.annotation.Resource;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

/**  
 * @Class Name : EgovFileTransfer.java
 * @Description : EgovFileTransfer
 * @
 * @  수정일         수정자                 수정내용
 * @ ---------   ---------   --------------------------------------------------------------
 * @ 2012. 7. 10.  서준식        최초생성
 * @ 2012. 7. 30.  이율경        커스터마이징
 * @ 2017.02. 27.  최두영        시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754]
 *  
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 7. 10.
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */
@Service("EgovMediaAndroidFileMngUtil")
public class EgovMediaAndroidFileMngUtil extends EgovAbstractServiceImpl {
    
    /** EgovCameraAndroidAPIService */
    @Resource(name = "EgovMediaAndroidAPIService")
    private EgovMediaAndroidAPIService egovMediaAndroidAPIService;

    private static final Logger LOGGER = Logger.getLogger(EgovMediaAndroidFileMngUtil.class.getClass());
    
    /** propertiesService */
    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;
    
    @Resource(name="egovFileIdGnrService")
    private EgovIdGnrService egovFileIdGnrService;
    
    
    public MediaAndroidAPIFileVO writeUploadedFile(MultipartFile file) throws Exception{
        
        String originFileName = file.getOriginalFilename();
        int index = originFileName.lastIndexOf(".");
        String fileExt = originFileName.substring(index + 1);
        String newName = "RECORD_" + getTimeStamp() + ".mp3";
        
        // 파일 경로 바꾸어야함.
        String filePath = propertiesService.getString("fileStorePath");
        
        MediaAndroidAPIFileVO fileVO = new MediaAndroidAPIFileVO();
        
        fileVO.setFileSn(egovFileIdGnrService.getNextIntegerId());
        fileVO.setFileStreCours(filePath);
        fileVO.setStreFileNm(newName);
        fileVO.setOrignlFileNm(originFileName);
        fileVO.setFileExtsn(fileExt);
        fileVO.setFileSize(Long.toString(file.getSize()));
        
        IOException excep = null;
        
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
                
                out.close();
            //2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 97-97
            } catch (NullPointerException e){
            	LOGGER.error("["+e.getClass()+"] Try/Catch... file: " + e.getMessage());
            } catch (Exception e) {
            	LOGGER.error("["+e.getClass()+"] Try/Catch... : " + e.getMessage());
                throw new EgovBizException("Fail to upload file : " + e.getMessage());
            } finally{
            	if(out != null){
	                try {
                        out.close();
	                    
	                } catch (IOException e) {
	                    LOGGER.debug("Fail to close fileoutputstrem : {}", e);
	                    excep = e;
	                }
            	}
            }
        }
        
        if(excep != null) {
        	throw new EgovBizException("Fail to close fileoutputstrem : " + excep.getMessage());
        }
        egovMediaAndroidAPIService.insertMediaRecordFile(fileVO);
        
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
        //2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 132-132
        }catch(NullPointerException e){
        	LOGGER.error("["+e.getClass()+"] Try/Catch...sdfCurrent : " + e.getMessage());
        } catch (Exception e) { 
        	LOGGER.error("["+e.getClass()+"] Try/Catch... : " + e.getMessage());
        }

        return rtnStr;
    }
}
