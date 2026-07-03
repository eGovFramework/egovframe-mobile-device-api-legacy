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
package egovframework.hyb.add.nwk.service;

import java.io.Serializable;
import java.util.List;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**  
 * @Class Name : NetworkAndroidAPIVO.java
 * @Description : NetworkAndroidAPIVO Class
 * @Modification Information  
 * @
 * @  수정일            수정자        수정내용
 * @ ---------        ---------    -------------------------------
 * @ 2012. 8. 20.        이율경        최초생성
 * 
 * @author 디바이스 API 실행환경 팀
 * @since 2012. 8. 20.
 * @version 1.0
 * @see
 * 
 */
@XmlRootElement
public class NetworkAndroidAPIXmlVO implements Serializable {
    
    private static final long serialVersionUID = 1L;

    /** 일련번호 */
    private int sn;
    
    /** 기기식별 */
    private String uuid;
    
    /** 네트워크 유형 */
    private String networktype;
    
    /** 사용여부 */
    private String useYn;
    
    /** successCode */
    private String successCode;
    
    /** 상세정보 */
    private NetworkAndroidAPIVO networkAndroidAPIVO;
    
    /** 목록 */
    private List<NetworkAndroidAPIVO> networkInfoList;

    /**
     * @return networkAndroidAPIVO을 반환한다.
     */
    public NetworkAndroidAPIVO getNetworkAndroidAPIVO() {
        return networkAndroidAPIVO;
    }

    /**
     * @param 파라미터 networkAndroidAPIVO을 networkAndroidAPIVO에 설정한다.
     */
    @XmlElement
    public void setNetworkAndroidAPIVO(NetworkAndroidAPIVO networkAndroidAPIVO) {
        this.networkAndroidAPIVO = networkAndroidAPIVO;
    }
    
    /**
     * @return networkInfoList을 반환한다.
     */
    public List<NetworkAndroidAPIVO> getNetworkInfoList() {
        return networkInfoList;
    }

    /**
     * @param 파라미터 networkInfoList을 networkInfoList에 설정한다.
     */
    @XmlElement
    public void setNetworkInfoList(List<NetworkAndroidAPIVO> networkInfoList) {
        this.networkInfoList = networkInfoList;
    }

    /**
     * @return successCode 반환한다.
     */
    public String getSuccessCode() {
        return successCode;
    }

    /**
     * @param 파라미터 successCode을 successCode에 설정한다.
     */
    @XmlElement
    public void setSuccessCode(String successCode) {
        this.successCode = successCode;
    }

    /**
     * @return  sn을 반환한다
     */
    public int getSn() {
        return sn;
    }

    /**
     * @param 파라미터 sn를 변수 sn에 설정한다.
     */
    @XmlElement
    public void setSn(int sn) {
        this.sn = sn;
    }

    /**
     * @return  uuid을 반환한다
     */
    public String getUuid() {
        return uuid;
    }

    /**
     * @param 파라미터 uuid를 변수 uuid에 설정한다.
     */
    @XmlElement
    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    /**
     * @return  networktype을 반환한다
     */
    public String getNetworktype() {
        return networktype;
    }

    /**
     * @param 파라미터 networktype를 변수 networktype에 설정한다.
     */
    @XmlElement
    public void setNetworktype(String networktype) {
        this.networktype = networktype;
    }

    /**
     * @return  useYn을 반환한다
     */
    public String getUseYn() {
        return useYn;
    }

    /**
     * @param 파라미터 useYn를 변수 useYn에 설정한다.
     */
    @XmlElement
    public void setUseYn(String useYn) {
        this.useYn = useYn;
    }
    

}
