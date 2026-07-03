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
package egovframework.hyb.add.acl.service.impl;

import java.util.List;

import javax.annotation.Resource;

import org.springframework.stereotype.Service;

import egovframework.hyb.add.acl.service.AcceleratorAndroidAPIDefaultVO;
import egovframework.hyb.add.acl.service.AcceleratorAndroidAPIVO;
import egovframework.hyb.add.acl.service.EgovAcceleratorAndroidAPIService;
import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;

/**  
 * @Class Name : EgovAcceleratorAPIServiceImpl.java
 * @Description : EgovAcceleratorAPIServiceImpl Class
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

@Service("EgovAcceleratorAndroidAPIService")
public class EgovAcceleratorAndroidAPIServiceImpl extends EgovAbstractServiceImpl implements EgovAcceleratorAndroidAPIService {
    
    /** AcceleratorAndroidAPIDAO */
    @Resource(name="AcceleratorAndroidAPIDAO")
    private AcceleratorAndroidAPIDAO acceleratorAPIDAO;

    /**
     * 가속도 정보를 등록한다.
     * @param vo - 등록할 정보가 담긴 AcceleratorAPIVO
     * @return 등록 결과
     * @exception Exception
     */
    public int insertAcceleratorInfo(AcceleratorAndroidAPIVO vo) throws Exception {        
        return acceleratorAPIDAO.insertAcceleratorInfo(vo);        
    }

    /**
     * 가속도 정보를 수정한다.
     * @param vo - 수정할 정보가 담긴 AcceleratorAPIVO
     * @return void형
     * @exception Exception
     */
    public void updateAcceleratorInfo(AcceleratorAndroidAPIVO vo) throws Exception {
        acceleratorAPIDAO.updateAcceleratorInfo(vo);
    }

    /**
     * 가속도 정보를 삭제한다.
     * @param vo - 삭제할 정보가 담긴 AcceleratorAPIVO
     * @return void형 
     * @exception Exception
     */
    public int deleteAcceleratorInfo(AcceleratorAndroidAPIVO vo) throws Exception {
        return acceleratorAPIDAO.deleteAcceleratorInfo(vo);
    }

    /**
     * 가속도 정보를 조회한다.
     * @param vo - 조회할 정보가 담긴 AcceleratorAPIVO
     * @return 조회한 가속도 정보
     * @exception Exception
     */
    public AcceleratorAndroidAPIVO selectAcceleratorInfo(AcceleratorAndroidAPIVO vo) throws Exception {
        AcceleratorAndroidAPIVO resultVO = acceleratorAPIDAO.selectAcceleratorInfo(vo);
        if (resultVO == null){
            throw processException("info.nodata.msg");
        }
        return resultVO;
    }

    /**
     * 가속도 정보 목록을 조회한다.
     * @param VO - 조회할 정보가 담긴 AcceleratorAPIDefaultVO
     * @return 가속도 정보 목록
     * @exception Exception
     */
    public List<?> selectAcceleratorInfoList(AcceleratorAndroidAPIDefaultVO searchVO) throws Exception {
        return acceleratorAPIDAO.selectAcceleratorInfoList(searchVO);
    }

    /**
     * 가속도 정보 총 갯수를 조회한다.
     * @param VO - 조회할 정보가 담긴 AcceleratorAPIDefaultVO
     * @return 가속도 정보 총 갯수
     * @exception
     */
    public int selectAcceleratorInfoListTotCnt(AcceleratorAndroidAPIDefaultVO searchVO) {
        return acceleratorAPIDAO.selectAcceleratorInfoListTotCnt(searchVO);
    }
    
}
