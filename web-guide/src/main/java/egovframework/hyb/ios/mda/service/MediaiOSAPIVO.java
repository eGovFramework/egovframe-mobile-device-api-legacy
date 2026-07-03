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
package egovframework.hyb.ios.mda.service;

import java.io.Serializable;

/**  
 * @Class Name : MediaiOSAPIVO.java
 * @Description : MediaiOSAPIVO Class
 * @Modification Information  
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------	  ---------   -------------------------------
 *   2012.07.30   이율경             최초생성
 *   2012.08.14   이해성             커스터마이징
 *   2020.07.29   신용호             Swagger 적용
 * 
 * @author 디바이스 API 실행환경 팀
 * @since 2012. 7. 30.
 * @version 1.0
 * @see
 * 
 */

public class MediaiOSAPIVO implements Serializable {

	private static final long serialVersionUID = -3847992567289110139L;

	/** 일련번호 */
		private String sn;
	
	/** 기기식별코드 */
		private String uuid;
	
	/** 파일 일련번호 */
		private String fileSn;
	
	/** 미디어구분코드 */
		private String mdCode;
	
	/** 미디어 제목 */
		private String mdSj;
	
	/** 사용여부 */
		private String useyn;
	
	/** 재생횟수 */
		private String revivCo;

	/**
	 * @return sn을 반환한다.
	 */
	public String getSn() {
		return sn;
	}

	/**
	 * @param 파라미터 sn을 sn에 설정한다.
	 */
	public void setSn(String sn) {
		this.sn = sn;
	}

	/**
	 * @return uuid을 반환한다.
	 */
	public String getUuid() {
		return uuid;
	}

	/**
	 * @param 파라미터 uuid을 uuid에 설정한다.
	 */
	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	/**
	 * @return fileSn을 반환한다.
	 */
	public String getFileSn() {
		return fileSn;
	}

	/**
	 * @param 파라미터 fileSn을 fileSn에 설정한다.
	 */
	public void setFileSn(String fileSn) {
		this.fileSn = fileSn;
	}

	/**
	 * @return mdCode을 반환한다.
	 */
	public String getMdCode() {
		return mdCode;
	}

	/**
	 * @param 파라미터 mdCode을 mdCode에 설정한다.
	 */
	public void setMdCode(String mdCode) {
		this.mdCode = mdCode;
	}

	/**
	 * @return mdSj을 반환한다.
	 */
	public String getMdSj() {
		return mdSj;
	}

	/**
	 * @param 파라미터 mdSj을 mdSj에 설정한다.
	 */
	public void setMdSj(String mdSj) {
		this.mdSj = mdSj;
	}

	/**
	 * @return useyn을 반환한다.
	 */
	public String getUseyn() {
		return useyn;
	}

	/**
	 * @param 파라미터 useyn을 useyn에 설정한다.
	 */
	public void setUseyn(String useyn) {
		this.useyn = useyn;
	}

	/**
	 * @return revivCo을 반환한다.
	 */
	public String getRevivCo() {
		return revivCo;
	}

	/**
	 * @param 파라미터 revivCo을 revivCo에 설정한다.
	 */
	public void setRevivCo(String revivCo) {
		this.revivCo = revivCo;
	}
	
}
