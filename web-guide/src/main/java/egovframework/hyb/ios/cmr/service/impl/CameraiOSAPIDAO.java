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
package egovframework.hyb.ios.cmr.service.impl;

import java.util.List;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.ios.cmr.service.CameraiOSAPIDefaultVO;
import egovframework.hyb.ios.cmr.service.CameraiOSAPIFileVO;
import egovframework.hyb.ios.cmr.service.CameraiOSAPIVO;

import org.springframework.stereotype.Repository;

/**  
 * @Class Name : CameraIOSAPIDAO.java
 * @Description : CameraIOSAPIDAO Class
 * @Modification Information  
 * @
 * @  수정일			수정자		수정내용
 * @ ---------		---------	-------------------------------
 * @ 2012. 7. 23.		이율경		최초생성
 * @ 2012. 8. 03.  		이해성       커스터마이징
 * @ 2026. 6. 26.       이백행        [2026년 컨트리뷰션] 불필요한 예외(throws Exception) 제거
 * 
 * @author 디바이스 API 개발환경 팀
 * @since 2012. 7. 23.
 * @version 1.0
 * @see
 * 
 */
@Repository("CameraiOSAPIDAO")
public class CameraiOSAPIDAO extends EgovComAbstractDAO {

	/**
	 * 이미지를 등록한다.
	 * @param vo - 등록할 정보가 담긴 CameraAPIVO
	 * @return 등록 결과
	 */
    public int insertCameraPhotoAlbum(CameraiOSAPIFileVO vo) {
    	return (Integer)insert("cameraiOSAPIDAO.insertCameraPhotoAlbum", vo);
    }
    
    /**
	 * 이미지 파일을 등록한다.
	 * @param vo - 등록할 파일 정보가 담긴 CameraIOSAPIFileVO
	 * @return 등록 결과
	 */
    public int insertCameraPhotoAlbumFile(CameraiOSAPIFileVO vo) {
    	return (Integer)insert("cameraiOSAPIDAO.insertCameraPhotoAlbumFile", vo);
    }
    
    /**
	 * 이미지 파일을 수정한다.
	 * @param vo - 등록할 정보가 담긴 CameraIOSAPIFileVO
	 * @return 수정 결과
	 */
    public int updateCameraPhotoAlbumInfoFile(CameraiOSAPIFileVO vo) {
    	return (Integer)update("cameraiOSAPIDAO.updateCameraPhotoAlbumFile", vo);
    }

    /**
	 * 이미지를 삭제한다.
	 * @param vo - 삭제할 파일 정보가 담긴 CameraAPIVO
	 * @return 삭제 결과
	 */
    public int deleteCameraPhotoAlbumInfo(CameraiOSAPIVO vo) {
    	return (Integer)delete("cameraiOSAPIDAO.deleteCameraPhotoAlbumInfo", vo);
    }
    
    /**
	 * 이미지 파일을  삭제한다.
	 * @param vo - 삭제할 파일 정보가 담긴 CameraIOSAPIFileVO
	 * @return 삭제 결과 
	 */
    public int deleteCameraPhotoAlbumInfoFile(CameraiOSAPIVO vo) {
    	return (Integer)delete("cameraiOSAPIDAO.deleteCameraPhotoAlbumInfoFile", vo);
    }

    /**
	 * 이미지 정보를 조회한다.
	 * @param vo - 조회할 정보가 담긴 CameraAPIVO
	 * @return 조회한 네트워크 정보
	 */
    public CameraiOSAPIVO selectCameraPhotoAlbumInfo(CameraiOSAPIVO vo) {
        return (CameraiOSAPIVO) selectOne("cameraiOSAPIDAO.selectCameraPhotoAlbumInfo", vo);
    }

    /**
	 * 이미지 정보 목록을 조회한다.
	 * @param vo - 조회할 정보가 담긴 CameraAPIDefaultVO
	 * @return 이미지 정보 목록
	 */
    public List<?> selectCameraPhotoAlbumInfoList(CameraiOSAPIDefaultVO searchVO) {
        return selectList("cameraiOSAPIDAO.selectCameraPhotoAlbumInfoList", searchVO);
    }
    
    /**
	 * 이미지 파일 정보를 조회한다.
	 * @param vo - 조회할 정보가 담긴 CameraIOSAPIFileVO
	 * @return 이미지 파일 정보
	 */
    public CameraiOSAPIFileVO selectImageFileInfo(CameraiOSAPIFileVO vo) {
        return (CameraiOSAPIFileVO) selectOne("cameraiOSAPIDAO.selectImageFileInfo", vo);
    }
    
    /**
	 * 이미지 제목 중복을 조회한다.
	 * @param vo - 조회할 정보가 담긴 CameraIOSAPIFileVO
	 * @return 파일연번 정보
	 */
    public CameraiOSAPIFileVO selectPhotoAlbumPhotoSj(CameraiOSAPIFileVO vo) {
        return (CameraiOSAPIFileVO) selectOne("cameraiOSAPIDAO.selectCameraPhotoAlbumPhotoSj", vo);
    }
}
