package egovframework.hyb.mbl.jai.service;

import java.io.Serializable;

/**  
 * @Class Name : JailbreakDetectionDeviceAPIVO
 * @Description : JailbreakDetectionDeviceAPIVO Class
 * @Modification Information  
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------   ---------   -------------------------------
 *   2016.07.26   신성학             최초 작성
 *   2020.07.29   신용호             Swagger 적용
 * 
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 07. 26
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by Ministry of Interior All right reserved.
 */

public class JailbreakDetectionDeviceAPIVO implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
    /** 일련번호 */
	    private int sn;
    
    /** 기기식별 */
	    private String uuid;
    
    /** OS */
	    private String os;
    
    /** 폰갭 버전 */
	    private String pgVer;
    
    /** 탈옥 및 루팅 여부 */
	    private String detection;

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
	/**
	 * @return  os을 반환한다
	 */
	public String getOs() {
		return os;
	}

	/**
	 * @param 파라미터 os를 변수 os에 설정한다.
	 */
	public void setOs(String os) {
		this.os = os;
	}
	
	/**
	 * @return  pgVer을 반환한다
	 */
	public String getPgVer() {
		return pgVer;
	}

	/**
	 * @param 파라미터 pgVer를 변수 pgVer에 설정한다.
	 */
	public void setPgVer(String pgVer) {
		this.pgVer = pgVer;
	}
        
	/**
	 * @return  detection을 반환한다
	 */
	public String getDetection() {
		return detection;
	}

	/**
	 * @param 파라미터 detection를 변수 detection에 설정한다.
	 */
	public void setDetection(String detection) {
		this.detection = detection;
	}	
    
	
}
