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
package egovframework.hyb.ios.mda.service.impl;

import java.util.List;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.ios.mda.service.MediaiOSAPIFileVO;
import egovframework.hyb.ios.mda.service.MediaiOSAPIVO;

import org.springframework.stereotype.Repository;

/**  
 * @Class Name : MediaiOSAPIDAO.java
 * @Description : MediaiOSAPIDAO Class
 * @Modification Information  
 * @
 * @  수정일			수정자		수정내용
 * @ ---------		---------	-------------------------------
 * @ 2012. 7. 30.		이율경		최초생성
 * @ 2012. 8. 14.		이해성       커스터마이징
 * @ 2026. 6. 26.       이백행        [2026년 컨트리뷰션] 불필요한 예외 제거
 * 
 * @author 디바이스 API 실행환경 팀
 * @since 2012. 7. 30.
 * @version 1.0
 * @see
 * 
 */
@Repository("MediaiOSAPIDAO")
public class MediaiOSAPIDAO extends EgovComAbstractDAO {

	/**
	 * 녹음 Media를 등록한다.
	 * @param vo - 등록할 정보가 담긴 CameraAPIVO
	 * @return 등록 결과
	 */
    public int insertMediaInfo(MediaiOSAPIFileVO vo) {
    	return (Integer)insert("mediaiOSAPIDAO.insertMediaInfo", vo);
    }
    
    /**
	 * 녹음 파일을 등록한다.
	 * @param vo - 등록할 파일 정보가 담긴 CameraiOSAPIFileVO
	 * @return 등록 결과
	 */
    public int insertMediaRecordFile(MediaiOSAPIFileVO vo) {
    	return (Integer)insert("mediaiOSAPIDAO.insertMediaRecordFile", vo);
    }
    
    /**
	 * 녹음 재생횟수를 수정한다.
	 * @param vo - 등록할 정보가 담긴 MediaiOSAPIFileVO
	 * @return 수정 결과
	 */
    public int updateMediaInfoRevivCo(MediaiOSAPIVO vo) {
    	return (Integer)update("mediaiOSAPIDAO.updateMediaInfoRevivCo", vo);
    }
    
	/**
	 * 미디어 정보를 조회한다.
	 * @param VO - 조회할 정보가 담긴 MediaiOSAPIVO
	 * @return 조회 목록
	 */
	public MediaiOSAPIFileVO selectMediaInfoDetail(MediaiOSAPIVO vo) {
		return (MediaiOSAPIFileVO) selectOne("mediaiOSAPIDAO.selectMediaInfoDetail", vo);
	}
	
	/**
	 * 미디어 목록을 조회한다.
	 * @param VO - 조회할 정보가 담긴 MediaiOSAPIDefaultVO
	 * @return 조회 목록
	 */
	public List<?> selectMediaInfoList(MediaiOSAPIVO searchVO) {
		return selectList("mediaiOSAPIDAO.selectMediaInfoList", searchVO);
	}
	
	/**
	 * 미디어 파일 정보를 조회한다.
	 * @param vo - 조회할 정보가 담긴 MediaiOSAPIFileVO
	 * @return 이미지 파일 정보
	 */
    public MediaiOSAPIFileVO selectMediaFileInfo(MediaiOSAPIFileVO vo) {
        return (MediaiOSAPIFileVO) selectOne("mediaiOSAPIDAO.selectMediaFileInfo", vo);
    }
}
