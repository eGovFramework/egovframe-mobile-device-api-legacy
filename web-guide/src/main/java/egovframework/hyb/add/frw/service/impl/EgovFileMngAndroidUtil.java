/**
 * 
 */
package egovframework.hyb.add.frw.service.impl;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
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
import egovframework.hyb.add.frw.service.EgovFileReaderWriterAndroidAPIService;
import egovframework.hyb.add.frw.service.FileReaderWriterAndroidAPIVO;
import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;
import egovframework.rte.fdl.cmmn.exception.BaseRuntimeException;
import egovframework.rte.fdl.cmmn.exception.EgovBizException;
import egovframework.rte.fdl.cmmn.exception.FdlException;
import egovframework.rte.fdl.idgnr.EgovIdGnrService;
import egovframework.rte.fdl.property.EgovPropertyService;

/**  
 * @Class Name : EgovFileTransfer.java
 * @Description : EgovFileTransfer
 * @
 * @  수정일         정자                 수정내용
 * @ ---------   ---------     ----------------------------------------------
 * @ 2012. 8. 6.   나신일                   최초생성
 * @ 2017.02.27    최두영        시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754]
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 8. 6
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */
@Service("egovFileMngAndroidUtil")
public class EgovFileMngAndroidUtil extends EgovAbstractServiceImpl {

    /** Logger */
	private static final Logger LOGGER = LoggerFactory.getLogger(EgovFileMngAndroidUtil.class);

    /** BUFFER_SIZE */
    private final static int BUFFER_SIZE = 2048;

    /** propertiesService */
    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;

    /** EgovIdGnrService */
    @Resource(name = "egovFileIdGnrService")
    private EgovIdGnrService egovFileIdGnrService;

    /** EgovFileReaderWriterAndroidAPIService */
    @Resource(name = "egovFileReaderWriterAndroidAPIService")
    private EgovFileReaderWriterAndroidAPIService egovFileReaderWriterAndroidAPIService;

    /**
     * 사용자가 전송한 파일을 업로드 한다.
     * 
     * @param file
     *            - 업로드된 파일 정보가 담긴 MultipartFile
     * @param fileVO
     *            - 파일 정보가 담긴 FileReaderWriterAndroidAPIVO
     */
    public FileReaderWriterAndroidAPIVO writeUploadedFile(MultipartFile file,
            FileReaderWriterAndroidAPIVO fileVO) {

        DeviceAPIFileUploadValidator.validateFrwUpload(file);

        String originFileName = file.getOriginalFilename();
        int index = originFileName.lastIndexOf(".");
        String fileExt = originFileName.substring(index + 1);
        String newName = "File_" + getTimeStamp();

        // fileVO에 값 셋팅
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

        if (!file.isEmpty()) {
            InputStream input = null;
            FileOutputStream out = null;
            try {
            	LOGGER.info("try to upload file");
                byte[] bytes = file.getBytes();
                input = new ByteArrayInputStream(bytes);

                File videoFile = new File(EgovWebUtil.filePathBlackList(propertiesService.getString("fileStorePath") + newName));
                out = new FileOutputStream(videoFile);
                int len = -1;
                byte[] fileBuffer = new byte[1024 * 8];
                while ((len = input.read(fileBuffer)) != -1) {
                	LOGGER.info("filesize: {}", String.valueOf(len));
                    out.write(fileBuffer, 0, len);
                }
            //2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 116-116    
            }catch(IOException e){
            	throw new BaseRuntimeException(e);
            } finally {
                try {
                    if (out != null) {
                        out.close();
                    }
                } catch (IOException e) {
                	throw new BaseRuntimeException(e);
                }
            }
        }

        egovFileReaderWriterAndroidAPIService.insertFileDetailInfo(fileVO);
        return fileVO;
    }

    /**
     * 선택된 파일에 대한 다운로드 기능을 처리한다.
     * 
     * @param request
     *            - HttpServletRequest
     * @param response
     *            - HttpServletResponse
     * @param fileVO
     *            - 파일 정보가 담긴 FileReaderWriterAndroidAPIVO
     */
    public void fileDownload(HttpServletRequest request,
            HttpServletResponse response, FileReaderWriterAndroidAPIVO fileVO) {

        DeviceAPIFileUploadValidator.assertSafeStoredFileName(fileVO.getStreFileNm());
        File file = new File(EgovWebUtil.filePathBlackList(propertiesService.getString("fileStorePath") + fileVO.getStreFileNm()));

        if (!file.exists()) {
            throw new BaseRuntimeException(fileVO.getStreFileNm());
        }
        if (!file.isFile()) {
            throw new BaseRuntimeException(fileVO.getStreFileNm());
        }

        byte[] buffer = new byte[BUFFER_SIZE];

        response.setContentType("video/quicktime");
        try {
			response.setHeader("Content-Disposition:", "attachment; filename="
			        + new String(fileVO.getOrignlFileNm().getBytes(), "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			throw new BaseRuntimeException(e);
		}
        response.setHeader("Content-Transfer-Encoding", "binary");
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
                }catch(IOException e){
                	throw new BaseRuntimeException(e);
                }
            }
            if (fin != null) {
                try {
                    fin.close();
                //2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 195-195
                }catch(IOException e){
                	throw new BaseRuntimeException(e);
                }
            }
        }

    }

    /**
     * 선택된 파일에 대한 삭제 기능을 처리한다.
     * 
     * @param fileVO
     *            - 파일 정보가 담긴 FileReaderWriterAndroidAPIVO
     */
    public boolean deleteFile(FileReaderWriterAndroidAPIVO fileVO) {

        File videoFile = new File(EgovWebUtil.filePathBlackList(propertiesService.getString("fileStorePath") + fileVO.getStreFileNm()));

        if (videoFile.exists()) {

            if (videoFile.isFile()) {
                if (videoFile.delete()) {
                	LOGGER.info("Success to remove file.");
                } else {
                	LOGGER.info("Fail to remove file.");
                }
            } else {
            	LOGGER.info("This is not file.");
            }
        } else {
        	LOGGER.info("There is no file to remove.");
        }

        int nCnt = 0;
        nCnt = egovFileReaderWriterAndroidAPIService
                .deleteFileInfo(fileVO);

        return nCnt > 0 ? true : false;
    }

    /**
     * yyyyMMddhhmmssSSS 패턴의 현재 날자를 반환한다.
     * 
     * @return String
     */
    private static String getTimeStamp() {
        String rtnStr = null;

        // 문자열로 변환하기 위한 패턴 설정(년도-월-일 시:분:초:초(자정이후 초))
        String pattern = "yyyyMMddhhmmssSSS";

        SimpleDateFormat sdfCurrent = new SimpleDateFormat(pattern,
                Locale.KOREA);
        Timestamp ts = new Timestamp(System.currentTimeMillis());

        rtnStr = sdfCurrent.format(ts.getTime());

        return rtnStr;
    }
}
