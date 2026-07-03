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
package egovframework.hyb.mbl.pus.service;

import java.util.List;

/**  
 * @Class Name : EgovPushAPIService.java
 * @Description : EgovPushAPIService Class
 * @Modification Information
 * @
 * @  수정일       수정자                 수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2016.06.20   신성학                 최초생성
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 06. 20
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by Ministry of Interior All right reserved.
 */
public interface EgovPushDeviceAPIService {
	
	/**
	 * 알람 정보를 등록한다.
	 * @param vo - 등록할 정보가 담긴 VibratorAPIVO
	 * @return 등록 결과
	 * @exception Exception
	 */
/*    int insertVibrator(PushDeviceAPIVO vo) throws Exception;*/
 
    
    /**
	 * Push Device 정보 목록을 조회한다.
	 * @param VO - 조회할 정보가 담긴 PushDeviceAPIDefaultVO
	 * @return 네트워크 정보 목록
	 * @exception Exception
	 */
    List<?> selectPushDeviceList(PushDeviceAPIDefaultVO searchVO) throws Exception;

	/**
	 * Push Notification을 위해 Device 정보를 등록한다.
	 * @param vo - 등록할 정보가 담긴 PushAPIVO
	 * @return 등록 결과
	 * @exception Exception
	 */
    int insertPushDevice(PushDeviceAPIVO vo) throws Exception;

	/**
	 * Push Notification을 서버에 요청한다.
	 * @param vo - 등록할 정보가 담긴 PushAPIVO
	 * @return 등록 결과
	 * @exception Exception
	 */
    int insertPushInfo(PushDeviceAPIVO vo) throws Exception;
    
	/**
	 * Push Notification 기기 상세 조회를 한다.
	 * @param vo - 등록할 정보가 담긴 PushDeviceAPIVO
	 * @return 조회 결과
	 * @exception Exception
	 */
    public PushDeviceAPIVO selectPushDevice(PushDeviceAPIVO vo) throws Exception;

    /**
	 * Push Notification 송신 메세지 조회를 한다.
	 * @param vo - 등록할 정보가 담긴 PushDeviceAPIVO
	 * @return 조회 결과
	 * @exception Exception
	 */
    List<?> selectPushMessageList(PushDeviceAPIVO vo) throws Exception;

    /**
     * Push Notification 등록된 기기가 있는지 조회를 한다.
     * @param VO
     * @return
     * @throws Exception
     */
    public int selectPushDeviceCount(PushDeviceAPIVO vo) throws Exception;
}
