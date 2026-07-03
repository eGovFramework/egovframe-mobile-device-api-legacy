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
package egovframework.hyb.add.gps.service.impl;

import java.util.List;

import egovframework.hyb.add.gps.service.EgovGPSAndroidAPIService;
import egovframework.hyb.add.gps.service.GPSAndroidAPIDefaultVO;
import egovframework.hyb.add.gps.service.GPSAndroidAPIVO;

import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;

import javax.annotation.Resource;

import org.springframework.stereotype.Service;

/**  
 * @Class Name : EgovGPSAndroidAPIServiceImpl.java
 * @Description : EgovGPSAndroidAPIServiceImpl Class
 * @Modification Information  
 * @
 * @  수정일              수정자                   수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2012.08.27    나신일                   최초생성
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 08.27
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

@Service("EgovGPSAndroidAPIService")
public class EgovGPSAndroidAPIServiceImpl extends EgovAbstractServiceImpl implements
        EgovGPSAndroidAPIService {

    /** GPSAPIDAO */
    @Resource(name = "GPSAndroidAPIDAO")
    private GPSAndroidAPIDAO gpsAPIDAO;

    /**
     * gps 정보를 등록한다.
     * 
     * @param vo
     *            - 등록할 정보가 담긴 GPSAPIVO
     * @return 등록 결과
     * @exception Exception
     */
    public int insertGPSInfo(GPSAndroidAPIVO vo) throws Exception {
        return gpsAPIDAO.insertGPSInfo(vo);
    }

    /**
     * gps 정보를 삭제한다.
     * 
     * @param vo
     *            - 삭제할 정보가 담긴 GPSAPIVO
     * @return void형
     * @exception Exception
     */
    public int deleteGPSInfo(GPSAndroidAPIVO vo) throws Exception {
        return gpsAPIDAO.deleteGPSInfo(vo);
    }

    /**
     * gps 정보 목록을 조회한다.
     * 
     * @param VO
     *            - 조회할 정보가 담긴 GPSAPIVO
     * @return gps 정보 목록
     * @exception Exception
     */
    public List<?> selectGPSInfoList(GPSAndroidAPIDefaultVO searchVO) throws Exception {
        return gpsAPIDAO.selectGPSInfoList(searchVO);
    }

    /**
     * gps 정보 총 갯수를 조회한다.
     * 
     * @param VO
     *            - 조회할 정보가 담긴 GPSAPIVO
     * @return gps 정보 총 갯수
     * @exception
     */
    public int selectGPSInfoListTotCnt(GPSAndroidAPIDefaultVO searchVO) {
        return gpsAPIDAO.selectGPSInfoListTotCnt(searchVO);
    }

}
