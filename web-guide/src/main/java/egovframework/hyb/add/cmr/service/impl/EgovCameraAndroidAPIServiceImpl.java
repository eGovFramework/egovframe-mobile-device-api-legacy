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
package egovframework.hyb.add.cmr.service.impl;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;

import egovframework.hyb.add.cmr.service.CameraAndroidAPIDefaultVO;
import egovframework.hyb.add.cmr.service.CameraAndroidAPIFileVO;
import egovframework.hyb.add.cmr.service.CameraAndroidAPIVO;
import egovframework.hyb.add.cmr.service.EgovCameraAndroidAPIService;

import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**  
 * @Class Name : EgovCameraAndroidAPIServiceImpl.java
 * @Description : EgovCameraAndroidAPIServiceImpl Class
 * @Modification Information  
 * @
 * @  수정일             수정자        수정내용
 * @ ---------        ---------    -------------------------------
 * @ 2012. 7. 23.      이율경        최초생성
 * @ 2017.02.27        최두영        시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754]
 * 
 * @author 디바이스 API 개발환경 팀
 * @since 2012. 7. 23.
 * @version 1.0
 * @see
 * 
 */
@Service("EgovCameraAndroidAPIService")
public class EgovCameraAndroidAPIServiceImpl extends EgovAbstractServiceImpl implements EgovCameraAndroidAPIService {

    /** CameraAndroidAPIDAO */
    @Resource(name="CameraAndroidAPIDAO")
    private CameraAndroidAPIDAO cameraAPIDAO;
    
    private static final Logger LOGGER = LoggerFactory.getLogger(EgovCameraAndroidAPIServiceImpl.class);
    
    /**
     * 이미지를 등록한다.
     * @param vo - 등록할 정보가 담긴 CameraAPIVO
     * @return void형
     * @exception Exception
     */
    public int insertCameraPhotoAlbum(CameraAndroidAPIVO vo, int fileSn) throws Exception {
        
        CameraAndroidAPIFileVO fileVO = new CameraAndroidAPIFileVO();
        fileVO.setFileSn(fileSn);
        fileVO.setPhotoSj(vo.getPhotoSj());
        fileVO.setUuid(vo.getUuid());
        fileVO.setUseyn("Y");
        
        return cameraAPIDAO.insertCameraPhotoAlbum(fileVO);
    }
    
    /**
     * 이미지 파일을 등록한다.
     * @param vo - 등록할 정보가 담긴 CameraAPIVO
     * @return void형
     * @exception Exception
     */
    public int insertCameraPhotoAlbumFile(CameraAndroidAPIFileVO vo) throws Exception {
        return cameraAPIDAO.insertCameraPhotoAlbumFile(vo);
    }
    
    /**
     * 이미지를 수정한다.
     * @param vo - 등록할 정보가 담긴 CameraAPIVO
     * @return void형
     * @exception Exception
     */
    public int updateCameraPhotoAlbumFile(CameraAndroidAPIVO vo, int fileSn) throws Exception {
        
        CameraAndroidAPIFileVO fileVO = new CameraAndroidAPIFileVO();
        fileVO.setFileSn(fileSn);
        fileVO.setSn(Integer.parseInt(vo.getSn()));
        
        return cameraAPIDAO.updateCameraPhotoAlbumInfoFile(fileVO);
    }

    /**
     * 이미지를 삭제한다.
     * @param vo - 삭제할 정보가 담긴 CameraAPIVO
     * @return void형
     * @exception Exception
     */
    public boolean deleteCameraPhotoAlbum(CameraAndroidAPIVO vo) throws Exception {
        
        int deleteCnt = cameraAPIDAO.deleteCameraPhotoAlbumInfo(vo);
        if(deleteCnt < 1) {
            return false;
        }
        deleteCnt = cameraAPIDAO.deleteCameraPhotoAlbumInfoFile(vo);
        if(deleteCnt < 1) {
            return false;
        }
        
        return true;
    }

    /**
     * 이미지 정보를 조회한다.
     * @param vo - 조회할 정보가 담긴 CameraAPIVO
     * @return 조회 결과
     * @exception Exception
     */
    public CameraAndroidAPIVO selectCameraPhotoAlbum(CameraAndroidAPIVO vo) throws Exception {
        return cameraAPIDAO.selectCameraPhotoAlbumInfo(vo);
    }

    /**
     * 이미지 정보 목록을 조회한다.
     * @param vo - 조회할 정보가 담긴 CameraAndroidAPIDefaultVO
     * @return 이미지 정보 목록
     * @exception Exception
     */
    public List<?> selectCameraPhotoAlbumList(CameraAndroidAPIDefaultVO searchVO) throws Exception {
        return cameraAPIDAO.selectCameraPhotoAlbumInfoList(searchVO);
    }
    
    /**
     * 이미지 파일을 조회한다.
     * @param VO - 조회할 정보가 담긴 CameraAndroidAPIFileVO
     * @return 파일 정보
     * @exception Exception
     */
    public boolean selectImageFileInf(HttpServletResponse response, CameraAndroidAPIFileVO vo) throws Exception {
        File file = null;
        FileInputStream fis = null;
    
        BufferedInputStream in = null;
        ByteArrayOutputStream bStream = null;
        
        CameraAndroidAPIFileVO fileVO = cameraAPIDAO.selectImageFileInfo(vo);
        if (fileVO == null) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "File access denied.");
            return false;
        }

        boolean errorFlag = true;
        
           try {
				file = new File(fileVO.getFileStreCours(), fileVO.getStreFileNm());
				fis = new FileInputStream(file);
   
				in = new BufferedInputStream(fis);
				bStream = new ByteArrayOutputStream();
   
				int imgByte;
				while ((imgByte = in.read()) != -1) {
				    bStream.write(imgByte);
				}
   
				String type = "";
      
				if (fileVO.getFileExtsn() != null && !"".equals(fileVO.getFileExtsn())) {
				    if ("jpg".equals(fileVO.getFileExtsn().toLowerCase())) {
				    type = "image/jpeg";
				    } else {
				    type = "image/" + fileVO.getFileExtsn().toLowerCase();
				    }
				    type = "image/" + fileVO.getFileExtsn().toLowerCase();
      
				} else {
					LOGGER.debug("Image fileType is null.");
				}
      
				response.setHeader("Content-Type", type);
				response.setContentLength(bStream.size());
      
				bStream.writeTo(response.getOutputStream());
      
				response.getOutputStream().flush();
				response.getOutputStream().close();
				
			//2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 195-195
            }catch(IOException e){
            LOGGER.error("["+e.getClass()+"] Try/Catch...Input/Output : ", e.getMessage());
            errorFlag = false;
            }catch(Exception e) {
            LOGGER.error("["+e.getClass()+"] Try/Catch... : ", e.getMessage());
            errorFlag = false;
            } finally {
            if (bStream != null) {
                try {
                    bStream.close();
                //2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 202-202
                } catch(IOException e){
            	LOGGER.error("["+e.getClass()+"] Try/Catch...bStream.close(); : " , e.getMessage());
            	errorFlag = false;
                }catch (Exception e) {
                LOGGER.error("["+e.getClass()+"] Try/Catch... : ", e.getMessage());
                errorFlag = false;
                }
            }
            if (in != null) {
                try {
                    in.close();
                //2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 210-210
                } catch(IOException e){
                	LOGGER.error("["+e.getClass()+"] Try/Catch...in.close() : " , e.getMessage());
                	errorFlag = false;
                }catch (Exception e) {
                	LOGGER.error("["+e.getClass()+"] Try/Catch... : ", e.getMessage());
                    errorFlag = false;
                }
            }
            if (fis != null) {
                try {
                    fis.close();
                //2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 218-218
                }catch(IOException e){
                	LOGGER.error("["+e.getMessage()+"] Try/Catch...fis.close() : " , e.getMessage());
                	errorFlag = false;
                }
               	catch (Exception e) {
               		LOGGER.error("["+e.getClass()+"] Try/Catch... : ", e.getMessage());
                    errorFlag = false;
                }
            }
        }
        
        return errorFlag;
    }

    /**
     * 이미지 제목 중복을 조회한다.
     * @param vo - 조회할 정보가 담긴 CameraAPIVO
     * @return 조회한 이미지 정보
     * @exception Exception
     */
    public CameraAndroidAPIFileVO selectCameraPhotoAlbumPhotoSj(CameraAndroidAPIVO vo) throws Exception {
        
        CameraAndroidAPIFileVO fileVO = new CameraAndroidAPIFileVO();
        fileVO.setPhotoSj(vo.getPhotoSj());
        
        return cameraAPIDAO.selectPhotoAlbumPhotoSj(fileVO);
    }
}
