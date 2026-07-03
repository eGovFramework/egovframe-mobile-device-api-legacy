/**
 * 
 */
package egovframework.hyb.add.ctt.service;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**  
 * @Class Name : ContactsAndroidAPIVO.java
 * @Description : ContactsAndroidAPIVO
 * @
 * @ 수정일                수정자             수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.08.13   나신일              최초생성
 *   2020.07.29   신용호              Swagger 적용
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 8. 13
 * @version 1.0
 * @see
 * 
 */
@XmlRootElement
public class ContactsAndroidAPIVO  implements Serializable {

    private static final long serialVersionUID = 1L;

    /** UUID(기기식별코드) */
        private String uuid;

    /** 연락처 ID */
        private int contactId;

    /** 새연락처 ID */
        private int newId;

    /** 연락처 이름 */
        private String name;

    /** 연락처 전화번호 */
        private String telNo;

    /** 연락처 전화번호 비교용 */
        private String telNoCompare;
    
    /** 연락처 이메일 */
        private String emails;

    /** 사용 여부 */
        private String useYn;

    /** 연락처 총 개수 */
        private int totCount;

    /** 연락처 리스트 */
        private String contactsList;

    /** resultState */
        private String resultState;

    /** resultMessage */
        private String resultMessage;

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
    public void setUuid(final String uuid) {
        this.uuid = uuid;
    }

    /**
     * @return id를 반환한다
     */
    public int getContactId() {
        return contactId;
    }

    /**
     * @param 파라미터
     *            id를 변수 id에 설정한다.
     */
    @XmlElement
    public void setContactId(final int contactId) {
        this.contactId = contactId;
    }

    /**
     * @return newId를 반환한다
     */
    public int getNewId() {
        return newId;
    }

    /**
     * @param 파라미터
     *            newId를 변수 newId에 설정한다.
     */
    @XmlElement
    public void setNewId(final int newId) {
        this.newId = newId;
    }

    /**
     * @return name을 반환한다
     */
    public String getName() {
        return name;
    }

    /**
     * @param 파라미터
     *            name을 변수 name에 설정한다.
     */
    @XmlElement
    public void setName(final String name) {
        this.name = name;
    }

    /**
     * @return telNo를 반환한다
     */
    public String getTelNo() {
        return telNo;
    }

    /**
     * @param 파라미터
     *            telNo를 변수 telNo에 설정한다.
     */
    @XmlElement
    public void setTelNo(final String telNo) {
        this.telNo = telNo;
    }

    /**
     * @return telNo를 반환한다
     */
    public String getTelNoCompare() {
        return telNoCompare;
    }

    /**
     * @param 파라미터
     *            telNo를 변수 telNo에 설정한다.
     */
    @XmlElement
    public void setTelNoCompare(final String telNoCompare) {
        this.telNoCompare = telNoCompare;
    }
    
    /**
     * @return emails를 반환한다
     */
    public String getEmails() {
        return emails;
    }

    /**
     * @param 파라미터
     *            emails를 변수 emails에 설정한다.
     */
    @XmlElement
    public void setEmails(final String emails) {
        this.emails = emails;
    }

    /**
     * @return useYn을 반환한다
     */
    public String getUseYn() {
        return useYn;
    }

    /**
     * @param 파라미터
     *            useYn를 변수 useYn에 설정한다.
     */
    @XmlElement
    public void setUseYn(final String useYn) {
        this.useYn = useYn;
    }

    /**
     * @return totCount를 반환한다
     */
    public int getTotCount() {
        return totCount;
    }

    /**
     * @param 파라미터
     *            totCount를 변수 totCount에 설정한다.
     */
    @XmlElement
    public void setTotCount(final int totCount) {
        this.totCount = totCount;
    }

    /**
     * @param contactsList를
     *            반환한다
     */
    public String getContactsList() {
        return contactsList;
    }

    /**
     * @param 파라미터
     *            contactsList를 변수 contactsList에 설정한다.
     */
    @XmlElement
    public void setContactsList(final String contactsList) {
        this.contactsList = contactsList;
    }

    /**
     * @param resultState를
     *            반환한다
     */
    public String getResultState() {
        return resultState;
    }

    /**
     * @param 파라미터
     *            resultState를 변수 resultState에 설정한다.
     */
    @XmlElement
    public void setResultState(final String resultState) {
        this.resultState = resultState;
    }

    /**
     * @param resultMessage를
     *            반환한다
     */
    public String getResultMessage() {
        return resultMessage;
    }

    /**
     * @param 파라미터
     *            resultMessage를 변수 resultMessage에 설정한다.
     */
    @XmlElement
    public void setResultMessage(final String resultMessage) {
        this.resultMessage = resultMessage;
    }
}
