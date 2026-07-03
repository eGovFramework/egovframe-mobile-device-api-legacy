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

import java.io.Serializable;

/**  
 * @Class Name : PushDeviceAPIVO.java
 * @Description : PushDeviceAPIVO Class
 * @Modification Information  
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------   ---------   -------------------------------
 *   2016.06.20   신성학             최초생성
 *   2020.07.29   신용호             Swagger 적용
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 06. 20
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

public class PushDeviceAPIVO implements Serializable {
	
    private static final long serialVersionUID = 1L;

	/** 일련번호 */
        private int sn;
    
    /** 기기식별 */
        private String uuid;
    
	/** 네트워크 디바이스 정보  */
        private String ntwrkDeviceInfo;
    
    /** 디바이스 명  */
        private String deviceNm;

    /** OS 버전  */
        private String osVer;
    
    /** 사용여부  */
        private String useYn;
    
    /** OS 구분  */
        private String osType;
    
    /** 디바이스 토큰 ID  */
        private String tokenId;
    
    /** Push 발송 메시지  */
        private String message;

	/** Push 발송 일시  */
        private String sndDt;
    
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

    public String getNtwrkDeviceInfo() {
		return ntwrkDeviceInfo;
	}

	public void setNtwrkDeviceInfo(String ntwrkDeviceInfo) {
		this.ntwrkDeviceInfo = ntwrkDeviceInfo;
	}

	public String getDeviceNm() {
		return deviceNm;
	}

	public void setDeviceNm(String deviceNm) {
		this.deviceNm = deviceNm;
	}

	public String getOsVer() {
		return osVer;
	}

	public void setOsVer(String osVer) {
		this.osVer = osVer;
	}

	public String getUseYn() {
		return useYn;
	}

	public void setUseYn(String useYn) {
		this.useYn = useYn;
	}

	public String getOsType() {
		return osType;
	}

	public void setOsType(String osType) {
		this.osType = osType;
	}

	public String getTokenId() {
		return tokenId;
	}

	public void setTokenId(String tokenId) {
		this.tokenId = tokenId;
	}

    public String getSndDt() {
		return sndDt;
	}

	public void setSndDt(String sndDt) {
		this.sndDt = sndDt;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

}
