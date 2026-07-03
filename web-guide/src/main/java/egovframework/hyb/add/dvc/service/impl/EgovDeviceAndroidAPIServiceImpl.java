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
package egovframework.hyb.add.dvc.service.impl;

import java.util.List;

import javax.annotation.Resource;

import org.springframework.stereotype.Service;

import egovframework.hyb.add.dvc.service.DeviceAndroidAPIDefaultVO;
import egovframework.hyb.add.dvc.service.DeviceAndroidAPIVO;
import egovframework.hyb.add.dvc.service.EgovDeviceAndroidAPIService;
import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;

/**  
 * @Class Name : EgovDeviceAPIServiceImpl.java
 * @Description : EgovDeviceAPIServiceImpl Class
 * @Modification Information  
 * @
 * @  수정일                 수정자                 수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2012.07.23    서형주                  최초생성
 * 
 * @author Device API 실행환경팀
 * @since 2012. 07. 23
 * @version 1.0
 * @see
 * 
 */

@Service("EgovDeviceAndroidAPIService")
public class EgovDeviceAndroidAPIServiceImpl extends EgovAbstractServiceImpl implements EgovDeviceAndroidAPIService {
    
    /** DeviceAndroidAPIDAO */
    @Resource(name="DeviceAndroidAPIDAO")
    private DeviceAndroidAPIDAO deviceAPIDAO;

    /**
     * 디바이스 정보를 등록한다.
     * @param vo - 등록할 정보가 담긴 DeviceAPIVO
     * @return 등록 결과
     * @exception Exception
     */
    public int insertDeviceInfo(DeviceAndroidAPIVO vo) throws Exception {        
        return deviceAPIDAO.insertDeviceInfo(vo);        
    }

    /**
     * 디바이스 정보를 수정한다.
     * @param vo - 수정할 정보가 담긴 DeviceAPIVO
     * @return void형
     * @exception Exception
     */
    public void updateDeviceInfo(DeviceAndroidAPIVO vo) throws Exception {
        deviceAPIDAO.updateDeviceInfo(vo);
    }

    /**
     * 디바이스 정보를 삭제한다.
     * @param vo - 삭제할 정보가 담긴 DeviceAPIVO
     * @return void형 
     * @exception Exception
     */
    public int deleteDeviceInfo(DeviceAndroidAPIVO vo) throws Exception {
        return deviceAPIDAO.deleteDeviceInfo(vo);
    }

    /**
     * 디바이스 정보를 조회한다.
     * @param vo - 조회할 정보가 담긴 DeviceAPIVO
     * @return 조회한 디바이스 정보
     * @exception Exception
     */
    public DeviceAndroidAPIVO selectDeviceInfo(DeviceAndroidAPIVO vo) throws Exception {
        DeviceAndroidAPIVO resultVO = deviceAPIDAO.selectDeviceInfo(vo);
        if (resultVO == null)
            throw processException("info.nodata.msg");
        return resultVO;
    }

    /**
     * 디바이스 정보 목록을 조회한다.
     * @param VO - 조회할 정보가 담긴 DeviceAPIDefaultVO
     * @return 디바이스 정보 목록
     * @exception Exception
     */
    public List<?> selectDeviceInfoList(DeviceAndroidAPIDefaultVO searchVO) throws Exception {
        return deviceAPIDAO.selectDeviceInfoList(searchVO);
    }

    /**
     * 디바이스 정보 총 갯수를 조회한다.
     * @param VO - 조회할 정보가 담긴 DeviceAPIDefaultVO
     * @return 디바이스 정보 총 갯수
     * @exception
     */
    public int selectDeviceInfoListTotCnt(DeviceAndroidAPIDefaultVO searchVO) {
        return deviceAPIDAO.selectDeviceInfoListTotCnt(searchVO);
    }
    
}
