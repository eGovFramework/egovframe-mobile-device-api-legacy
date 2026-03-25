package egovframework.hyb.add.cmr.service.impl;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Locale;

import javax.annotation.Resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import egovframework.hyb.add.cmr.service.CameraAndroidAPIFileVO;
import egovframework.hyb.add.cmr.service.EgovCameraAndroidAPIService;
import egovframework.hyb.ios.cmr.service.impl.EgovWebUtil;
import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;
import egovframework.rte.fdl.cmmn.exception.EgovBizException;
import egovframework.rte.fdl.idgnr.EgovIdGnrService;
import egovframework.rte.fdl.property.EgovPropertyService;

/**  
 * @Class Name : EgovFileTransfer.java
 * @Description : EgovFileTransfer
 * @
 * @  수정일                 수정자                 수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2012. 7. 10.  서준식                  최초생성
 * @ 2012. 7. 23.  이율경                  커스터마이징
 * @ 2017.02.27    최두영        시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754]
 *  
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 7. 10.
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */
@Service("EgovCameraAndroidFileMngUtil")
public class EgovCameraAndroidFileMngUtil extends EgovAbstractServiceImpl {
    
    /** EgovCameraAndroidAPIService */
    @Resource(name = "EgovCameraAndroidAPIService")
    private EgovCameraAndroidAPIService egovCameraAndroidAPIService;

    private static final Logger LOGGER = LoggerFactory.getLogger(EgovCameraAndroidFileMngUtil.class);
    
    /** propertiesService */
    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;
    
    @Resource(name="egovFileIdGnrService")
    private EgovIdGnrService egovFileIdGnrService;
    
    
    public CameraAndroidAPIFileVO writeUploadedFile(MultipartFile file) throws Exception{
        
        String originFileName = file.getOriginalFilename();
        int index = originFileName.lastIndexOf(".");
        String fileExt = originFileName.substring(index + 1);
        String newName = "IMAGE_" + getTimeStamp() + ".jpg";
        
        String filePath = propertiesService.getString("fileStorePath");
        
        CameraAndroidAPIFileVO fileVO = new CameraAndroidAPIFileVO();
        
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
            //2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 95-95
            }catch(IOException e){
            	LOGGER.error("["+e.getClass()+"] Try/Catch...bytes : " + e.getMessage());
            	throw new EgovBizException("Fail to open FileOutPutStream : " + e.getMessage());
            }catch (Exception e) {
            	//LOGGER.debug("Fail to upload file : {}", e.getMessage());
            	LOGGER.error("["+e.getClass()+"] Fail to upload file : ", e.getMessage());
                throw new EgovBizException("Fail to upload file : " + e.getMessage());
            }finally{
                try {
                    if(out != null){
                        out.close();
                    }
                    
                } catch(IOException e) {
                    LOGGER.debug("Fail to close fileoutputstrem : {}", e.getMessage());
                    excep = e;
                }
            }
        }
        
        if(excep != null) {
        	throw new EgovBizException("Fail to close fileoutputstrem : " + excep.getMessage());
        }
        egovCameraAndroidAPIService.insertCameraPhotoAlbumFile(fileVO);
        
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
        //2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 130-130
        } catch(NullPointerException e){
        	LOGGER.error("["+e.getClass()+"] Try/Catch... sdfCurrent : " , e.getMessage());
        } catch (Exception e) {            
        	LOGGER.error("["+e.getClass()+"] Try/Catch... : ", e.getMessage());
        }

        return rtnStr;
    }
}
