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
package egovframework.hyb.add.cmr.service;

import java.io.Serializable;

/**  
 * @Class Name : CameraAndroidAPIVO.java
 * @Description : CameraAndroidAPIVO Class
 * @Modification Information  
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------   ---------   -------------------------------
 * @ 2012.07.23   이율경              최초생성
 * @ 2020.07.29   신용호              Swagger 적용
 * 
 * @author 디바이스 API 개발환경 팀
 * @since 2012. 7. 23.
 * @version 1.0
 * @see
 * 
 */
public class CameraAndroidAPIVO implements Serializable {

    /** serialVersion UID*/
    private static final long serialVersionUID = 1L;
    
    /** 일련번호 */
        private String sn;
    
    /** 기기식별 */
        private String uuid;
    
    /** 사진제목 */
        private String photoSj;
    
    /** 파일연번 */
        private String fileSn;
    
    /** 활성화여부 */
        private String useyn;

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
     * @return photoSj을 반환한다.
     */
    public String getPhotoSj() {
        return photoSj;
    }

    /**
     * @param 파라미터 photoSj을 photoSj에 설정한다.
     */
    public void setPhotoSj(String photoSj) {
        this.photoSj = photoSj;
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

}
