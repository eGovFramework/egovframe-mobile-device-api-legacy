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
package egovframework.hyb.ios.cps.service;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**  
 * @Class Name : CompassiOSAPIVO.java
 * @Description : CompassiOSAPIVO Class
 * @Modification Information  
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.07.23   서형주             최초생성
 *   2012.08.27   서준식             iOS용 패키지로 변경
 *   2020.07.29   신용호             Swagger 적용
 * 
 * @author Device API 실행환경팀
 * @since 2012. 07. 30
 * @version 1.0
 * @see
 * 
 */
@XmlRootElement
public class CompassiOSAPIVO implements Serializable {
	
    private static final long serialVersionUID = 1L;

	/** 일련번호 */
        private int sn;
    
    /** 기기식별 */
        private String uuid;
    
    /** 기기방향 */
        private String drc;
    
    /** 정확도 */
        private String accrcy;
    
    /** timestamp */
        private String timestamp;
    
    /** 사용여부 */
        private String useYn;
    
	/**
	 * @return  sn을 반환한다
	 */ 
	public int getSn() {
		return sn;
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
	 * @return  drc을 반환한다
	 */
	public String getDrc() {
		return drc;
	}

	/**
	 * @param 파라미터 drc를 변수 drc에 설정한다.
	 */
	@XmlElement
	public void setDrc(String drc) {
		this.drc = drc;
	}

	/**
	 * @return  accrcy을 반환한다
	 */
	public String getAccrcy() {
		return accrcy;
	}

	/**
	 * @param 파라미터 accrcy를 변수 accrcy에 설정한다.
	 */
	@XmlElement
	public void setAccrcy(String accrcy) {
		this.accrcy = accrcy;
	}

	/**
	 * @return  timestamp을 반환한다
	 */
	public String getTimestamp() {
		return timestamp;
	}

	/**
	 * @param 파라미터 timestamp를 변수 timestamp에 설정한다.
	 */
	@XmlElement
	public void setTimestamp(String timestamp) {
		this.timestamp = timestamp;
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

	/**
	 * @param 파라미터 sn를 변수 sn에 설정한다.
	 */
	@XmlElement
	public void setSn(int sn) {
		this.sn = sn;
	}
    
}
