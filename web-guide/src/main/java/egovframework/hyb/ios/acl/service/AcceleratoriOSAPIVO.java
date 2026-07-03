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
package egovframework.hyb.ios.acl.service;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**  
 * @Class Name : AcceleratoriOSAPIVO.java
 * @Description : AcceleratoriOSAPIVO Class
 * @Modification Information  
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.07.23   서형주              최초생성
 *   2012.08.16   서준식              json 버전으로 변경
 *   2020.08.11   신용호              Swagger 적용
 *   
 * 
 * @author Device API 실행환경팀
 * @since 2012. 07. 23
 * @version 1.0
 * @see
 * 
 */
@XmlRootElement
public class AcceleratoriOSAPIVO implements Serializable {
	
    private static final long serialVersionUID = 1L;

	/** 일련번호 */
        private int sn;
    
    /** 기기식별 */
        private String uuid;
    
    /** x */
        private String xaxis;
    
    /** y */
        private String yaxis;
    
    /** z */
        private String zaxis;
    
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
	 * @return  xaxis을 반환한다
	 */
	public String getXaxis() {
		return xaxis;
	}

	/**
	 * @param 파라미터 xaxis를 변수 xaxis에 설정한다.
	 */
	@XmlElement
	public void setXaxis(String xaxis) {
		this.xaxis = xaxis;
	}

	/**
	 * @return  yaxis을 반환한다
	 */
	public String getYaxis() {
		return yaxis;
	}

	/**
	 * @param 파라미터 yaxis를 변수 yaxis에 설정한다.
	 */
	@XmlElement
	public void setYaxis(String yaxis) {
		this.yaxis = yaxis;
	}

	/**
	 * @return  zaxis을 반환한다
	 */
	public String getZaxis() {
		return zaxis;
	}

	/**
	 * @param 파라미터 zaxis를 변수 zaxis에 설정한다.
	 */
	@XmlElement
	public void setZaxis(String zaxis) {
		this.zaxis = zaxis;
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
