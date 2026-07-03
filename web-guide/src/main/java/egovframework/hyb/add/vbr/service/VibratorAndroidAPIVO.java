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
package egovframework.hyb.add.vbr.service;

import java.io.Serializable;

/**  
 * @Class Name : VibratorAndroidAPIVO.java
 * @Description : VibratorAndroidAPIVO Class
 * @Modification Information  
 * @
 * @ 수정일                수정자             수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.08.16   이율경             최초생성
 *   2020.07.29   신용호             Swagger 적용
 * 
 * @author 디바이스 API 실행환경 팀
 * @since 2012. 8. 16.
 * @version 1.0
 * @see
 * 
 */

public class VibratorAndroidAPIVO implements Serializable {
    
    private static final long serialVersionUID = 1L;

    /** 일련번호 */
        private int sn;
    
    /** 기기식별 */
        private String uuid;
    
    /** 사용여부 */
        private String timeStamp;

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

    public void setTimeStamp(String timeStamp) {
        this.timeStamp = timeStamp;
    }

    public String getTimeStamp() {
        return timeStamp;
    }
    

}
