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

import egovframework.com.cmm.vo.DefaultSearchVO;
/**  
 * @Class Name : NetworkAndroidAPIDefaultVO.java
 * @Description : NetworkAndroidAPIDefaultVO Class
 * @Modification Information  
 * @
 * @ 수정일         수정자              수정내용
 * @ ----------   ---------------   -------------------------------
 *   2012.08.20   이율경              최초생성
 *   2020.09.07   신용호              Swagger 적용
 * 
 * @author 디바이스 API 실행환경 팀
 * @since 2012. 8. 20.
 * @version 1.0
 * @see
 * 
 */
public class NetworkAndroidAPIDefaultVO extends DefaultSearchVO {
    
	private static final long serialVersionUID = -5668384239748862550L;

	/** 기기식별 */
        private String uuid;
    
    /** 네트워크 유형 */
        private String networktype;

    public String getUuid() {
		return uuid;
	}

	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	public String getNetworktype() {
		return networktype;
	}

	public void setNetworktype(String networktype) {
		this.networktype = networktype;
	}

}
