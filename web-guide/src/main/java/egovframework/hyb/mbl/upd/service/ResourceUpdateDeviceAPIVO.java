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
package egovframework.hyb.mbl.upd.service;

import java.io.Serializable;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

/**  
 * @Class Name : VibratorAPIVO.java
 * @Description : VibratorAPIVO Class
 * @Modification Information  
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.07.18   이해성             최초생성
 *   2020.07.29   신용호             Swagger 적용
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 07. 18
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

@ApiModel
public class ResourceUpdateDeviceAPIVO implements Serializable {
	
    private static final long serialVersionUID = 1L;

	/** 일련번호 */
    @ApiModelProperty(value="일련번호")
    private int sn;

	/** 리소스 버전  */
    @ApiModelProperty(value="리소스 버전")
    private String resVersion;

    @ApiModelProperty(value="앱ID")
	private String appId = "";
    
    @ApiModelProperty(value="업데이트 상세내용")
    private String updateContent = "";

    @ApiModelProperty(value="업데이트 날짜")
    private String updDt = "";
    
	/** 저장된 파일 이름 */
    @ApiModelProperty(value="저장된 파일 이름")
	private String streFileNm;
	
	/** 원 파일 이름  */
    @ApiModelProperty(value="원 파일 이름")
	private String orignlFileNm;
    
    /** 기기식별 */
    @ApiModelProperty(value="기기식별코드")
    private String uuid;
    
    /** OS 구분  */
    @ApiModelProperty(value="OS 구분")
    private String osType;

    /** ZIP 파일 SHA-256 해시 */
    @ApiModelProperty(value="ZIP 파일 SHA-256 해시")
    private String fileSha256;
    
    public String getResVersion() {
		return resVersion;
	}

	public void setResVersion(String resVersion) {
		this.resVersion = resVersion;
	}

    public String getAppId() {
		return appId;
	}

	public void setAppId(String appId) {
		this.appId = appId;
	}

	public String getUpdateContent() {
		return updateContent;
	}

	public void setUpdateContent(String updateContent) {
		this.updateContent = updateContent;
	}

	public String getUpdDt() {
		return updDt;
	}

	public void setUpdDt(String updDt) {
		this.updDt = updDt;
	}

	public String getStreFileNm() {
		return streFileNm;
	}
	
	public void setStreFileNm(String streFileNm) {
		this.streFileNm = streFileNm;
	}
	
	public String getOrignlFileNm() {
		return orignlFileNm;
	}
	
	public void setOrignlFileNm(String orignlFileNm) {
		this.orignlFileNm = orignlFileNm;
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

	public String getOsType() {
		return osType;
	}

	public void setOsType(String osType) {
		this.osType = osType;
	}

	public String getFileSha256() {
		return fileSha256;
	}

	public void setFileSha256(String fileSha256) {
		this.fileSha256 = fileSha256;
	}

}
