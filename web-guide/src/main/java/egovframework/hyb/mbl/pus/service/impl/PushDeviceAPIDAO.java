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
package egovframework.hyb.mbl.pus.service.impl;

import java.util.List;

import org.springframework.stereotype.Repository;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.mbl.pus.service.PushDeviceAPIDefaultVO;
import egovframework.hyb.mbl.pus.service.PushDeviceAPIVO;


/**  
 * @Class Name : PushAPIDAO.java
 * @Description : PushAPI DAO Class
 * @Modification Information  
 * @
 * @  수정일      수정자                 수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2016.06.20   신성학               최초생성
 *   2026.06.26   이백행               [2026년 컨트리뷰션] 불필요한 예외 제거
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 06. 20
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by Ministry of Interior All right reserved.
 */

@Repository("PushDeviceAPIDAO")
public class PushDeviceAPIDAO extends EgovComAbstractDAO {

    /**
	 * Push Device 정보 목록을 조회한다.
	 * @param vo - 조회할 정보가 담긴 PushDeviceAPIDefaultVO
	 * @return Push Device 정보 목록
	 */
    public List<?> selectPushDeviceList(PushDeviceAPIDefaultVO searchVO) {
        return selectList("pushDeviceAPIDAO.selectPushDeviceList", searchVO);
    }

	/**
	 * Push Device 정보를 등록한다.
	 * @param vo - 등록할 정보가 담긴 PushDeviceAPIVO
	 * @return 등록 결과
	 */
    public int insertPushDevice(PushDeviceAPIVO vo) {
        return (Integer)insert("pushDeviceAPIDAO.insertPushDevice", vo);
    }

	/**
	 * Push Notification 정보를 등록한다.
	 * @param vo - 등록할 정보가 담긴 PushDeviceAPIVO
	 * @return 등록 결과
	 */
    public int insertPushInfo(PushDeviceAPIVO vo) {
        return (Integer)insert("pushDeviceAPIDAO.insertVibratorInfo", vo);
    }
	/**
	 * Push Notification 기기 상세 조회를 한다.
	 * @param vo - 등록할 정보가 담긴 PushDeviceAPIVO
	 * @return 조회 결과
	 */
    public PushDeviceAPIVO selectPushDevice(PushDeviceAPIVO vo) {
        return (PushDeviceAPIVO) selectOne("pushDeviceAPIDAO.selectPushDevice", vo);
    }

	/**
	 * Push Notification 송신 메세지 조회를 한다.
	 * @param vo - 등록할 정보가 담긴 PushDeviceAPIVO
	 * @return 조회 결과
	 */
    public List<?> selectPushMessageList(PushDeviceAPIVO vo) {
        return selectList("pushDeviceAPIDAO.selectPushMessageList", vo);
    }

    /**
     * Push Notification 등록된 기기가 있는지 조회를 한다.
     * @param vo
     * @return
     */
    public int selectPushDeviceCount(PushDeviceAPIVO vo) {
    	return (Integer)selectOne("pushDeviceAPIDAO.selectPushDeviceCount", vo);
    }

}
