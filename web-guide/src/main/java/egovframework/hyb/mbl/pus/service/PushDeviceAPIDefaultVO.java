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

import egovframework.com.cmm.vo.DefaultSearchVO;

import io.swagger.annotations.ApiModelProperty;

/**  
 * @Class Name : PushDeviceAPIDefaultVO.java
 * @Description : PushDeviceAPIDefaultVO Class
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
public class PushDeviceAPIDefaultVO extends DefaultSearchVO {

	private static final long serialVersionUID = 1607939443103082103L;

    @ApiModelProperty(value = "기기식별코드", required = true)
    private String uuid;

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }
}
