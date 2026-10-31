package egovframework.hyb.add.mda.service.impl;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Locale;

import javax.annotation.Resource;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import egovframework.com.cmm.security.DeviceAPIFileUploadValidator;
import egovframework.hyb.add.mda.service.EgovMediaAndroidAPIService;
import egovframework.hyb.add.mda.service.MediaAndroidAPIFileVO;
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
    
    
    public MediaAndroidAPIFileVO writeUploadedFile(MultipartFile file) {
        
        DeviceAPIFileUploadValidator.validateMdaUpload(file);

        String originFileName = file.getOriginalFilename();
        int index = originFileName.lastIndexOf(".");
        String fileExt = originFileName.substring(index + 1);
        String newName = "RECORD_" + getTimeStamp() + ".mp3";
        
        // 파일 경로 바꾸어야함.
        String filePath = propertiesService.getString("fileStorePath");
        
        MediaAndroidAPIFileVO fileVO = new MediaAndroidAPIFileVO();
        
        try {
			fileVO.setFileSn(egovFileIdGnrService.getNextIntegerId());
		} catch (FdlException e) {
			throw new BaseRuntimeException(e);
		}
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
                
                File videoFile = new File(EgovWebUtil.filePathBlackList(filePath + newName));
                out = new FileOutputStream(videoFile);
                int nextChar;
                while((nextChar = input.read()) != -1){
                    out.write(nextChar);
                    out.flush();
                    
                }
                
                out.close();
            //2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 97-97
            } catch (IOException e) {
            	throw new BaseRuntimeException(e);
            } finally{
            	if(out != null){
	                try {
                        out.close();
	                } catch (IOException e) {
	                	throw new BaseRuntimeException(e);
	                }
            	}
            }
        }

        egovMediaAndroidAPIService.insertMediaRecordFile(fileVO);
        
        return fileVO;
    }
    
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
