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
package egovframework.hyb.add.itf.service;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

/**
 * @Class Name : InterfaceAndroidAPIVO.java
 * @Description : InterfaceAndroidAPIVO Class
 * @Modification Information  
 * @
 * @ 수정일                수정자             수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.07.09   나신일             최초생성
 *   2020.07.29   신용호             Swagger 적용
 * 
 * @author 모바일 디바이스 API 팀
 * @since 2012. 07. 09
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

@XmlRootElement
@ApiModel
public class InterfaceAndroidAPIVO implements Serializable {

    private static final long serialVersionUID = 1L;

    /** 일련번호 */
    @ApiModelProperty(value="일련번호")
    private int sn;

    /** 기기식별코드 */
    @ApiModelProperty(value="기기식별코드")
    private String uuid;

    /** 아이디 */
    @ApiModelProperty(value="아이디")
    private String userId;

    /** 비밀번호 */
    @ApiModelProperty(value="비밀번호")
    private String userPw;

    /** E-mail */
    @ApiModelProperty(value="이메일")
    private String emails;

    /** resultState */
    @ApiModelProperty(value="결과 코드")
    private String resultState;

    /** resultMessage */
    @ApiModelProperty(value="결과 메시지")
    private String resultMessage;

    /**
     * @return sn을 반환한다
     */
    public int getSn() {
        return sn;
    }

    /**
     * @param 파라미터
     *            sn를 변수 sn에 설정한다.
     */
    @XmlElement
    public void setSn(int sn) {
        this.sn = sn;
    }

    /**
     * @return uuid을 반환한다
     */
    public String getUuid() {
        return uuid;
    }

    /**
     * @param 파라미터
     *            uuid를 변수 uuid에 설정한다.
     */
    @XmlElement
    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    /**
     * @param userId를
     *            반환한다
     */
    public String getUserId() {
        return userId;
    }

    /**
     * @param 파라미터
     *            userId를 변수 userId에 설정한다.
     */
    @XmlElement
    public void setUserId(String userId) {
        this.userId = userId;
    }

    /**
     * @param userPw를
     *            반환한다
     */
    @XmlTransient
    public String getUserPw() {
        return userPw;
    }

    /**
     * @param 파라미터
     *            userPw를 변수 userPw에 설정한다.
     */
    @XmlElement
    public void setUserPw(String userPw) {
        this.userPw = userPw;
    }

    /**
     * @param emails를
     *            반환한다
     */
    public String getEmails() {
        return emails;
    }

    /**
     * @param 파라미터
     *            emails를 변수 emails에 설정한다.
     */
    @XmlElement
    public void setEmails(String emails) {
        this.emails = emails;
    }

    /**
     * @param emails를
     *            반환한다
     */
    public String getResultState() {
        return resultState;
    }

    /**
     * @param 파라미터
     *            emails를 변수 emails에 설정한다.
     */
    @XmlElement
    public void setResultState(String resultState) {
        this.resultState = resultState;
    }

    /**
     * @param emails를
     *            반환한다
     */
    public String getResultMessage() {
        return resultMessage;
    }

    /**
     * @param 파라미터
     *            emails를 변수 emails에 설정한다.
     */
    @XmlElement
    public void setResultMessage(String resultMessage) {
        this.resultMessage = resultMessage;
    }
}
