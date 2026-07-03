package egovframework.hyb.add.vbr.service;

import java.util.List;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**  
 * @Class Name : VibratorAndroidAPIXMLVO.java
 * @Description : VibratorAndroidAPIXMLVO Class
 * @Modification Information  
 * @
 * @ 수정일         수정자              수정내용
 * @ ----------   ---------------   -------------------------------
 *   2012.08.16   이율경              최초생성
 *   2020.09.07   신용호              Swagger 적용
 * 
 * @author 디바이스 API 실행환경 팀
 * @since 2012. 8. 16.
 * @version 1.0
 * @see
 * 
 */
@XmlRootElement
public class VibratorAndroidAPIXmlVO {

    /** 기기식별 */
	    private String uuid;
    
    /** 사용여부 */
        private String timeStamp;
    
    /** 등록 성공 여부 */
        private String message;
    
    /** 알림설정 정보 */
        private List<VibratorAndroidAPIVO> vibratorAndroidAPIList;

    /**
     * @return uuid을 반환한다.
     */
    public String getUuid() {
        return uuid;
    }

    /**
     * @param 파라미터 uuid을 uuid에 설정한다.
     */
    @XmlElement
    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    /**
     * @return timeStamp을 반환한다.
     */
    public String getTimeStamp() {
        return timeStamp;
    }

    /**
     * @param 파라미터 timeStamp을 timeStamp에 설정한다.
     */
    @XmlElement
    public void setTimeStamp(String timeStamp) {
        this.timeStamp = timeStamp;
    }

    /**
     * @return vibratorAndroidAPIList을 반환한다.
     */
    public List<VibratorAndroidAPIVO> getVibratorAndroidAPIList() {
        return vibratorAndroidAPIList;
    }

    /**
     * @param 파라미터 vibratorAndroidAPIList을 vibratorAndroidAPIList에 설정한다.
     */
    @XmlElement
    public void setVibratorAndroidAPIList(
            List<VibratorAndroidAPIVO> vibratorAndroidAPIList) {
        this.vibratorAndroidAPIList = vibratorAndroidAPIList;
    }

    /**
     * @return message을 반환한다.
     */
    public String getMessage() {
        return message;
    }

    /**
     * @param 파라미터 message을 message에 설정한다.
     */
    @XmlElement
    public void setMessage(String message) {
        this.message = message;
    }
    
}
