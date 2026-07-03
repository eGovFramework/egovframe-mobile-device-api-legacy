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
package egovframework.hyb.add.mda.service.impl;

import java.util.List;

import org.springframework.stereotype.Repository;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.add.mda.service.MediaAndroidAPIFileVO;
import egovframework.hyb.add.mda.service.MediaAndroidAPIVO;

/**  
 * @Class Name : MediaAndroidAPIDAO.java
 * @Description : MediaAndroidAPIDAO Class
 * @Modification Information  
 * @
 * @  수정일            수정자        수정내용
 * @ ---------        ---------    -------------------------------
 * @ 2012. 7. 30.        이율경        최초생성
 * 
 * @author 디바이스 API 실행환경 팀
 * @since 2012. 7. 30.
 * @version 1.0
 * @see
 * 
 */
@Repository("MediaAndroidAPIDAO")
public class MediaAndroidAPIDAO extends EgovComAbstractDAO {

    /**
     * 녹음 Media를 등록한다.
     * @param vo - 등록할 정보가 담긴 CameraAPIVO
     * @return 등록 결과
     * @exception Exception
     */
    public int insertMediaInfo(MediaAndroidAPIFileVO vo) throws Exception {
        return (Integer)insert("mediaAndroidAPIDAO.insertMediaInfo", vo);
    }
    
    /**
     * 녹음 파일을 등록한다.
     * @param vo - 등록할 파일 정보가 담긴 CameraAndroidAPIFileVO
     * @return 등록 결과
     * @exception Exception
     */
    public int insertMediaRecordFile(MediaAndroidAPIFileVO vo) throws Exception {
        return (Integer)insert("mediaAndroidAPIDAO.insertMediaRecordFile", vo);
    }
    
    /**
     * 녹음 재생횟수를 수정한다.
     * @param vo - 등록할 정보가 담긴 MediaAndroidAPIFileVO
     * @return 수정 결과
     * @exception Exception
     */
    public int updateMediaInfoRevivCo(MediaAndroidAPIVO vo) throws Exception {
        return (Integer)update("mediaAndroidAPIDAO.updateMediaInfoRevivCo", vo);
    }
    
    /**
     * 미디어 정보를 조회한다.
     * @param VO - 조회할 정보가 담긴 MediaAndroidAPIVO
     * @return 조회 목록
     * @exception Exception
     */
    public MediaAndroidAPIFileVO selectMediaInfoDetail(MediaAndroidAPIVO vo) throws Exception {
        return (MediaAndroidAPIFileVO) selectOne("mediaAndroidAPIDAO.selectMediaInfoDetail", vo);
    }
    
    /**
     * 미디어 목록을 조회한다.
     * @param VO - 조회할 정보가 담긴 MediaAndroidAPIDefaultVO
     * @return 조회 목록
     * @exception Exception
     */
    public List<?> selectMediaInfoList(MediaAndroidAPIVO searchVO) throws Exception {
        return selectList("mediaAndroidAPIDAO.selectMediaInfoList", searchVO);
    }
    
    /**
     * 미디어 파일 정보를 조회한다.
     * @param vo - 조회할 정보가 담긴 MediaAndroidAPIFileVO
     * @return 이미지 파일 정보
     * @exception Exception
     */
    public MediaAndroidAPIFileVO selectMediaFileInfo(MediaAndroidAPIFileVO vo) throws Exception {
        return (MediaAndroidAPIFileVO) selectOne("mediaAndroidAPIDAO.selectMediaFileInfo", vo);
    }
}
