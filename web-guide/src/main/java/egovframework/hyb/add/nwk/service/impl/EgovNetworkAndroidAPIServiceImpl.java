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
package egovframework.hyb.add.nwk.service.impl;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import egovframework.hyb.add.nwk.service.EgovNetworkAndroidAPIService;
import egovframework.hyb.add.nwk.service.NetworkAndroidAPIDefaultVO;
import egovframework.hyb.add.nwk.service.NetworkAndroidAPIVO;
import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;

/**  
 * @Class Name : EgovNetworkAndroidAPIServiceImpl.java
 * @Description : EgovNetworkAndroidAPIServiceImpl Class
 * @Modification Information  
 * @
 * @ 수정일         수정자        수정내용
 * @ ----------   ---------   -----------------------------------------------------------
 * @ 2012.08.20   이율경        최초생성
 * @ 2017.02.27   최두영        시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754]
 *   2020.09.07   신용호        Content-Type 수정
 *           
 * @author 디바이스 API 실행환경 팀
 * @since 2012. 8. 20.
 * @version 1.0
 * @see
 * 
 */
@Service("EgovNetworkAndroidAPIService")
public class EgovNetworkAndroidAPIServiceImpl extends EgovAbstractServiceImpl implements EgovNetworkAndroidAPIService {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(EgovNetworkAndroidAPIServiceImpl.class);
    
    /** NetworkAPIDAO */
    @Resource(name="NetworkAndroidAPIDAO")
    private NetworkAndroidAPIDAO networkAndroidAPIDAO;

    /**
     * 네트워크 정보를 등록한다.
     * @param vo - 등록할 정보가 담긴 NetworkAPIVO
     * @return 등록 결과
     * @exception Exception
     */
    public int insertNetworkInfo(NetworkAndroidAPIVO vo) throws Exception {    
        return (Integer)networkAndroidAPIDAO.insertNetworkInfo(vo);  
    }

    /**
     * 네트워크 정보를 수정한다.
     * @param vo - 수정할 정보가 담긴 NetworkAPIVO
     * @return void형
     * @exception Exception
     */
    public int updateNetworkInfo(NetworkAndroidAPIVO vo) throws Exception {
        return (Integer)networkAndroidAPIDAO.updateNetworkInfo(vo);
    }

    /**
     * 네트워크 정보를 삭제한다.
     * @param vo - 삭제할 정보가 담긴 NetworkAPIVO
     * @return void형 
     * @exception Exception
     */
    public int deleteNetworkInfo(NetworkAndroidAPIVO vo) throws Exception {
        return (Integer)networkAndroidAPIDAO.deleteNetworkInfo(vo);
    }

    /**
     * 네트워크 정보를 조회한다.
     * @param vo - 조회할 정보가 담긴 NetworkAPIVO
     * @return 조회한 네트워크 정보
     * @exception Exception
     */
    public NetworkAndroidAPIVO selectNetworkInfo(NetworkAndroidAPIVO vo) throws Exception {
        NetworkAndroidAPIVO resultVO = networkAndroidAPIDAO.selectNetworkInfo(vo);
        if (resultVO == null)
            throw processException("info.nodata.msg");
        return resultVO;
    }

    /**
     * 네트워크 정보 목록을 조회한다.
     * @param VO - 조회할 정보가 담긴 NetworkAPIVO
     * @return 네트워크 정보 목록
     * @exception Exception
     */
    public List<?> selectNetworkInfoList(NetworkAndroidAPIDefaultVO searchNetworkVO) throws Exception {
        return networkAndroidAPIDAO.selectNetworkInfoList(searchNetworkVO);
    }
    
    /**
     * 미디어 파일을 조회한다.
     * @param mp3FilePath
     * @return 파일 정보
     * @exception Exception
     */
    public boolean selectMediaFileInf(HttpServletResponse response, String mp3FilePath) throws Exception {
        File file = null;
        FileInputStream fis = null;
    
        BufferedInputStream in = null;
        ByteArrayOutputStream bStream = null;
        
        boolean errorFlag = true;
        
        try {
            file = new File(mp3FilePath + "owlband.mp3");
            fis = new FileInputStream(file);
    
            in = new BufferedInputStream(fis);
            bStream = new ByteArrayOutputStream();
    
            int imgByte;
            while ((imgByte = in.read()) != -1) {
                bStream.write(imgByte);
            }
    
            response.setHeader("Content-Type","audio/mp3");
            response.setContentLength(bStream.size());
        
            bStream.writeTo(response.getOutputStream());
        
            response.getOutputStream().flush();
            response.getOutputStream().close();
        //2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 149-149
        }catch(IOException e){
        	LOGGER.error("["+e.getClass()+"] Try/Catch...file : " , e.getMessage());
        } catch(Exception e) {
        	LOGGER.error("["+e.getClass()+"] Try/Catch... : " + e.getMessage());
            errorFlag = false;
        } finally {
            if (bStream != null) {
                try {
                    bStream.close();
                  //2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 156-156
                }catch(IOException e){
                	LOGGER.error("["+e.getClass()+"] Try/Catch...bStream : " , e.getMessage());
                } catch(Exception e) {
                	LOGGER.error("["+e.getClass()+"] Try/Catch... : " + e.getMessage());
                    errorFlag = false;
                }
            }
            if (in != null) {
                try {
                    in.close();
                  //2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 164-164
                }catch(IOException e){
                	LOGGER.error("["+e.getClass()+"] Try/Catch...in : " , e.getMessage());
                } catch(Exception e) {
                	LOGGER.error("["+e.getClass()+"] Try/Catch... : " + e.getMessage());
                    errorFlag = false;
                }
            }
            if (fis != null) {
            	try {
                    fis.close();
                  //2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 172-172
                }catch(IOException e){
                	LOGGER.error("["+e.getClass()+"] Try/Catch...fis : " , e.getMessage());
                } catch(Exception e) {
                	LOGGER.error("["+e.getClass()+"] Try/Catch... : " + e.getMessage());
                    errorFlag = false;
                }
            }
            
        }
        return errorFlag;
    }

}
