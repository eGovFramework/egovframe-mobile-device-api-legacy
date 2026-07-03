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
package egovframework.hyb.add.dvc.service;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**  
 * @Class Name : DeviceAPIVO.java
 * @Description : DeviceAPIVO Class
 * @Modification Information  
 * @
 * @ 수정일                수정자             수정내용
 * @ ----------   ---------   -------------------------------
 * @ 2012.07.23   서형주             최초생성
 * @ 2020.07.29   신용호             Swagger 적용
 * 
 * @author Device API 실행환경팀
 * @since 2012. 07. 23
 * @version 1.0
 * @see
 * 
 */
@XmlRootElement
public class DeviceAndroidAPIVO implements Serializable {
    
    private static final long serialVersionUID = 1L;

    /** 일련번호 */
        private int sn;
    
    /** 기기식별 */
        private String uuid;
    
    /** OS */
        private String os;
    
    /** 전화번호 */
        private String telno;
    
    /** 스토리지 정보  */
        private String strgeInfo;
    
    /** 네트워크 디바이스 정보  */
        private String ntwrkDeviceInfo;
    
    /** 폰갭 버전 */
        private String pgVer;
    
    /** 디바이스 명  */
        private String deviceNm;
    
    /** 활성화 여부  */
        private String useYn;

    /**
     * @return  sn을 반환한다
     */
    public int getSn() {
        return sn;
    }

    /**
     * @param 파라미터 sn를 변수 sn에 설정한다.
     */
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
    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    /**
     * @return  os을 반환한다
     */
    public String getOs() {
        return os;
    }

    /**
     * @param 파라미터 os를 변수 os에 설정한다.
     */
    public void setOs(String os) {
        this.os = os;
    }

    /**
     * @return  telno을 반환한다
     */
    public String getTelno() {
        return telno;
    }

    /**
     * @param 파라미터 telno를 변수 telno에 설정한다.
     */
    public void setTelno(String telno) {
        this.telno = telno;
    }

    /**
     * @return  strgeInfo을 반환한다
     */
    public String getStrgeInfo() {
        return strgeInfo;
    }

    /**
     * @param 파라미터 strgeInfo를 변수 strgeInfo에 설정한다.
     */
    public void setStrgeInfo(String strgeInfo) {
        this.strgeInfo = strgeInfo;
    }

    /**
     * @return  ntwrkDeviceInfo을 반환한다
     */
    public String getNtwrkDeviceInfo() {
        return ntwrkDeviceInfo;
    }

    /**
     * @param 파라미터 ntwrkDeviceInfo를 변수 ntwrkDeviceInfo에 설정한다.
     */
    public void setNtwrkDeviceInfo(String ntwrkDeviceInfo) {
        this.ntwrkDeviceInfo = ntwrkDeviceInfo;
    }

    /**
     * @return  pgVer을 반환한다
     */
    public String getPgVer() {
        return pgVer;
    }

    /**
     * @param 파라미터 pgVer를 변수 pgVer에 설정한다.
     */
    public void setPgVer(String pgVer) {
        this.pgVer = pgVer;
    }

    /**
     * @return  deviceNm을 반환한다
     */
    public String getDeviceNm() {
        return deviceNm;
    }

    /**
     * @param 파라미터 deviceNm를 변수 deviceNm에 설정한다.
     */
    public void setDeviceNm(String deviceNm) {
        this.deviceNm = deviceNm;
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
    public void setUseYn(String useYn) {
        this.useYn = useYn;
    }

    
}
