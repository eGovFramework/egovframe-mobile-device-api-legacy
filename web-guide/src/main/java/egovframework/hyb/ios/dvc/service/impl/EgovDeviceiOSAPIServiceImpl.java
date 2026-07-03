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
package egovframework.hyb.ios.dvc.service.impl;

import java.util.List;

import egovframework.hyb.ios.dvc.service.DeviceiOSAPIVO;
import egovframework.hyb.ios.dvc.service.EgovDeviceiOSAPIService;

import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;

import javax.annotation.Resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**  
 * @Class Name : EgovDeviceiOSAPIServiceImpl.java
 * @Description : EgovDeviceiOSAPIServiceImpl Class
 * @Modification Information  
 * @
 * @  수정일       수정자                   수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2012.07.30    서준식                   최초생성
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 07.30
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

@Service("egovDeviceiOSAPIService")
public class EgovDeviceiOSAPIServiceImpl extends EgovAbstractServiceImpl implements EgovDeviceiOSAPIService {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(EgovDeviceiOSAPIServiceImpl.class);
	
	/** DeviceAPIDAO */
    @Resource(name="deviceiOSAPIDAO")
    private DeviceiOSAPIDAO deviceiOSAPIDAO;

	/**
	 * 디바이스 정보를 등록한다.
	 * @param vo - 등록할 정보가 담긴 DeviceiOSAPIVO
	 * @return 등록 결과
	 * @exception Exception
	 */
    public void insertDeviceInfo(DeviceiOSAPIVO vo) throws Exception {
    	LOGGER.debug(vo.toString());
    	deviceiOSAPIDAO.insertDeviceInfo(vo);   
    }

    /**
	 * 디바이스 정보를 삭제한다.
	 * @param vo - 삭제할 정보가 담긴 DeviceiOSAPIVO
	 * @return void형 
	 * @exception Exception
	 */
    public void deleteDeviceInfo(DeviceiOSAPIVO vo) throws Exception {
    	deviceiOSAPIDAO.deleteDeviceInfo(vo);
    }

    /**
	 * 디바이스 정보를 조회한다.
	 * @param vo - 조회할 정보가 담긴 DeviceiOSAPIVO
	 * @return 조회한 디바이스 정보
	 * @exception Exception
	 */
    public DeviceiOSAPIVO selectDeviceInfo(DeviceiOSAPIVO vo) throws Exception {
    	DeviceiOSAPIVO resultVO = deviceiOSAPIDAO.selectDeviceInfo(vo);
        if (resultVO == null)
            throw processException("info.nodata.msg");
        return resultVO;
    }

    /**
	 * 디바이스 정보 목록을 조회한다.
	 * @param VO - 조회할 정보가 담긴 DeviceiOSAPIVO
	 * @return 디바이스 정보 목록
	 * @exception Exception
	 */
    public List<?> selectDeviceInfoList(DeviceiOSAPIVO vo) throws Exception {
        return deviceiOSAPIDAO.selectDeviceInfoList(vo);
    }

    /**
	 * 디바이스 정보 총 갯수를 조회한다.
	 * @param VO - 조회할 정보가 담긴 DeviceiOSAPIVO
	 * @return 디바이스 정보 총 갯수
	 * @exception
	 */
    public int selectDeviceInfoListTotCnt(DeviceiOSAPIVO vo) {
		return deviceiOSAPIDAO.selectDeviceInfoListTotCnt(vo);
	}
    
}
