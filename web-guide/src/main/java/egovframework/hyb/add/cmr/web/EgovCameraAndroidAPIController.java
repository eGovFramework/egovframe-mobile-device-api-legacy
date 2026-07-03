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
package egovframework.hyb.add.cmr.web;

import java.util.List;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.multipart.MultipartFile;

import egovframework.hyb.add.cmr.service.CameraAndroidAPIDefaultVO;
import egovframework.hyb.add.cmr.service.CameraAndroidAPIFileVO;
import egovframework.hyb.add.cmr.service.CameraAndroidAPIVO;
import egovframework.hyb.add.cmr.service.CameraAndroidAPIXmlVO;
import egovframework.hyb.add.cmr.service.EgovCameraAndroidAPIService;
import egovframework.com.cmm.security.DeviceAPIAuthSupport;
import egovframework.hyb.add.cmr.service.impl.EgovCameraAndroidFileMngUtil;
import egovframework.rte.fdl.property.EgovPropertyService;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;

/**  
 * @Class Name : EgovCameraAndroidAPIController.java
 * @Description : EgovCameraAndroidAPIController Class
 * @Modification Information  
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.07.23   이율경              최초생성
 *   2020.08.11   신용호              Swagger 적용
 * 
 * @author 디바이스 API 개발환경 팀
 * @since 2012. 7. 23.
 * @version 1.0
 * @see
 * 
 */
@Controller
public class EgovCameraAndroidAPIController {

    /** EgovCameraAndroidAPIService */
    @Resource(name = "EgovCameraAndroidAPIService")
    private EgovCameraAndroidAPIService egovCameraAndroidAPIService;
    
    /** propertiesService */
    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;
    
    /** EgovFileMngUtil */
    @Resource(name = "EgovCameraAndroidFileMngUtil")
    private EgovCameraAndroidFileMngUtil egovFileMngUtil;
    
    
    /**
     * 이미지 파일을 등록한다. (업로드)
     * @param file - 이미지 파일 정보가 담긴 MultipartFile
     * @param fileVO - 목록 조회조건 정보가 담긴 CameraAndroidAPIVO
     * @return boolean
     * @exception Exception
     */
    @ApiOperation(value="Camera 이미지파일 등록", notes="[Android] Camera 이미지파일 등록한다.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "file", value = "이미지파일", required = true, dataType = "__file", paramType = "form"),
    })
    @RequestMapping(value="/cmr/photoAlbumImageUpload.do", method=RequestMethod.POST)
    public @ResponseBody boolean fileUpload(@RequestParam("file") MultipartFile file, CameraAndroidAPIVO vo, 
            HttpServletRequest request) throws Exception{
        
        if (!file.isEmpty()) {
            
            CameraAndroidAPIFileVO fileVO = egovFileMngUtil.writeUploadedFile(file);
            
            egovCameraAndroidAPIService.insertCameraPhotoAlbum(vo, fileVO.getFileSn());
            
            return true;
        } else {
            
            return false;
        }
    }
    
    /**
     * 이미지 파일을 수정한다. (업로드)
     * @param file - 이미지 파일 정보가 담긴 MultipartFile
     * @param fileVO - 목록 조회조건 정보가 담긴 CameraAndroidAPIVO
     * @return boolean
     * @exception Exception
     */
    @ApiOperation(value="Camera 이미지파일 수정", notes="[Android] Camera 이미지파일 수정한다.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "file", value = "이미지파일", required = true, dataType = "__file", paramType = "form"),
    })
    @RequestMapping(value="/cmr/photoAlbumImageUpdate", method=RequestMethod.POST)
    public @ResponseBody boolean fileUpdate(@RequestParam("file") MultipartFile file, CameraAndroidAPIVO vo, 
            HttpServletRequest request) throws Exception{
        
        if (!file.isEmpty()) {
            
            CameraAndroidAPIFileVO fileVO = egovFileMngUtil.writeUploadedFile(file);
            
            egovCameraAndroidAPIService.updateCameraPhotoAlbumFile(vo, fileVO.getFileSn());
            
            return true;
        } else {
            
            return false;
        }
    }
    
    /**
     * 이미지 목록을 조회한다.
     * @param searchVO - 조회할 정보가 담긴 NetworkAPIDefaultVO
     * @return jsonView
     * @exception Exception
     */
    @ApiOperation(value="Camera 이미지 목록조회", notes="[Android] Camera 이미지 목록을 조회한다.")
    @ApiImplicitParams({
    	@ApiImplicitParam(name = "pageIndex", value = "현재 페이지", required = true, dataType = "int", paramType = "query"),
    })
    @SuppressWarnings("unchecked")
	@RequestMapping(value="/cmr/cameraPhotoAlbumList.do")
    public @ResponseBody CameraAndroidAPIXmlVO selectCameraPhotoAlbumList(
            @ModelAttribute("searchVO") CameraAndroidAPIDefaultVO searchVO,
            SessionStatus status)
            throws Exception {

        int firstIndex = (searchVO.getPageIndex()-1) * searchVO.getRecordCountPerPage();
        searchVO.setFirstIndex(firstIndex);
        
        List<CameraAndroidAPIFileVO> photoAlbumList = (List<CameraAndroidAPIFileVO>) egovCameraAndroidAPIService.selectCameraPhotoAlbumList(searchVO);
        
        CameraAndroidAPIXmlVO cameraAndroidAPIVOList = new CameraAndroidAPIXmlVO();
        cameraAndroidAPIVOList.setCameraAndroidAPIVOList(photoAlbumList);
        
        return cameraAndroidAPIVOList;
    }
    
    /**
     * 이미지 상세 정보를 조회한다.
     * @param cameraVO - 조회할 정보가 담긴 CameraAPIVO
     * @param searchVO - 목록 조회조건 정보가 담긴 CameraAPIDefaultVO
     * @param bindingResult
     * @param status
     * @return jsonView
     * @exception Exception
     */
    @ApiOperation(value="Camera 이미지 세부정보 조회", notes="[Android] Camera 이미지 세부정보를 조회한다.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "sn", value = "일련번호", required = true, dataType = "int", paramType = "query"),
    })
    @RequestMapping(value="/cmr/cameraPhotoAlbumDetail.do")
    public @ResponseBody CameraAndroidAPIXmlVO selectPhotoAlbum(CameraAndroidAPIVO vo,
            HttpServletRequest request, SessionStatus status)
            throws Exception {

        vo.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, vo.getUuid()));
        CameraAndroidAPIVO cameraVO = egovCameraAndroidAPIService.selectCameraPhotoAlbum(vo);
        
        CameraAndroidAPIXmlVO cameraAndroidAPIXmlVO = new CameraAndroidAPIXmlVO();
        cameraAndroidAPIXmlVO.setCameraAndroidAPIVO(cameraVO);
        
        return cameraAndroidAPIXmlVO;
    }
    
    /**
     * 이미지 파일을 조회한다.
     * @param fileVO - 조회할 정보가 담긴 CameraAndroidAPIFileVO
     * @param model
     * @param response
     * @return jsonView
     * @exception Exception
     */
    @ApiOperation(value="Camera 이미지 다운로드", notes="[Android] Camera 이미지 다운로드 한다.")
    @ApiImplicitParams({
    	@ApiImplicitParam(name = "fileSn", value = "파일연번", required = true, dataType = "int", paramType = "query"),
    })
    @RequestMapping("/cmr/getImage.do")
    public void getImageInf(@RequestParam("fileSn") String fileSn,
            @RequestParam(value = "uuid", required = false) String uuid,
            HttpServletRequest request, HttpServletResponse response) throws Exception {

        if (fileSn != null && !"".equals(fileSn)) {
            CameraAndroidAPIFileVO vo = new CameraAndroidAPIFileVO();
            vo.setFileSn(Integer.parseInt(fileSn));
            vo.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, uuid));
            egovCameraAndroidAPIService.selectImageFileInf(response, vo);
        }
    }
    
    /**
     * 이미지를 삭제한다.
     * @param sn - 조회할 정보가 담긴 String
     * @return jsonView
     * @exception Exception
     */
    @ApiOperation(value="Camera 이미지정보 삭제", notes="[Android] Camera 이미지정보를 삭제한다.")
    @ApiImplicitParams({
    	@ApiImplicitParam(name = "sn", value = "일련번호", required = true, dataType = "int", paramType = "query"),
    })
    @RequestMapping(value="/cmr/deleteCameraPhotoAlbum.do")
    public @ResponseBody CameraAndroidAPIXmlVO deleteCameraPhotoAlbum(CameraAndroidAPIVO vo,
            HttpServletRequest request, SessionStatus status)
            throws Exception {

        CameraAndroidAPIXmlVO cameraAndroidAPIXmlVO = new CameraAndroidAPIXmlVO();
        vo.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, vo.getUuid()));

        CameraAndroidAPIVO cameraVO = egovCameraAndroidAPIService.selectCameraPhotoAlbum(vo);
        if (cameraVO == null) {
            cameraAndroidAPIXmlVO.setDeleteCheck("false");
            return cameraAndroidAPIXmlVO;
        }

        Boolean deleteCheck = egovCameraAndroidAPIService.deleteCameraPhotoAlbum(cameraVO);
        cameraAndroidAPIXmlVO.setDeleteCheck(deleteCheck ? "true" : "false");

        return cameraAndroidAPIXmlVO;
    }
 
    /**
     * 이미지 제목 중복을 조회한다.
     * @param cameraVO - 조회할 정보가 담긴 CameraAPIVO
     * @param bindingResult
     * @param status
     * @return jsonView
     * @exception Exception
     */
    @ApiOperation(value="Camera 이미지 제목 중복 조회", notes="[Android] Camera 이미지 제목 중복을 조회한다.")
    @ApiImplicitParams({
    	@ApiImplicitParam(name = "photoSj", value = "사진제목", required = true, dataType = "string", paramType = "query"),
    })
    @RequestMapping(value="/cmr/cameraPhotoAlbumCheck.do")
    public @ResponseBody CameraAndroidAPIXmlVO selectPhotoAlbumPhoSj( CameraAndroidAPIVO vo,
            SessionStatus status)
            throws Exception {
        
        CameraAndroidAPIFileVO cameraVO = egovCameraAndroidAPIService.selectCameraPhotoAlbumPhotoSj(vo);
        
        CameraAndroidAPIVO newVO = new CameraAndroidAPIVO();
        if(cameraVO != null) {
            
            newVO.setSn(String.format("%d", cameraVO.getSn()));
        }
        
        CameraAndroidAPIXmlVO cameraAndroidAPIXmlVO = new CameraAndroidAPIXmlVO();
        cameraAndroidAPIXmlVO.setCameraAndroidAPIVO(newVO);
        
        return cameraAndroidAPIXmlVO;
    }
}
