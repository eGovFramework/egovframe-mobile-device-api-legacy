package egovframework.hyb.mbl.bar.service;

import java.io.Serializable;

/**  
 * @Class Name : BarcodescannerAPIVO.java
 * @Description : BarcodescannerAPIVO Class
 * @Modification Information  
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------   ---------   -------------------------------
 *   2016.07.26   신성학             최초생성
 *   2020.07.29   신용호             Swagger 적용
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 07. 26
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

public class BarcodescannerAPIVO implements Serializable {

	 private static final long serialVersionUID = 1L;
	 
	 /** 일련번호 */
	 	 private int sn;
	
	 /** 바코드 타입 */
	 	 private String codeType;
	 
	 /** 바코드 내용 */
	 	 private String codeText;
	 
	 /** 사용여부  */
	 	 private String useYn;
	 	 
	 /** 저장 일시  */
	 	 private String sndDt;
	
	
	 /** * @return  sn을 반환한다	 */
	 public int getSn() {
		 return sn;
		 }

	/** * @param 파라미터 sn를 변수 sn에 설정한다. */
	 public void setSn(int sn) {
		 this.sn = sn;
		 }
	 
	 /** * @return  codeType을 반환한다	 */
	 public String getCodeType() {
		 return codeType;
		 }

	 /** * @param 파라미터 codeType를 변수 codeType에 설정한다. */
	 public void setCodeType(String codeType) {
		 this.codeType = codeType;
		}
	 
	 /** * @return  codeText을 반환한다	 */
	 public String getCodeText() {
		 return codeText;
		 }

	 /** * @param 파라미터 codeText를 변수 codeText에 설정한다. */
	 public void setCodeText(String codeText) {
		 this.codeText = codeText;
		}
	 
	 /** * @param sndDt을 반환한다. */
	    public String getSndDt() {
			return sndDt;
		}

	 /** * @param 파라미터 sndDt를 변수 sndDt에 설정한다. */
		public void setSndDt(String sndDt) {
			this.sndDt = sndDt;
		}

		/** * @param useYn을 반환한다. */		
		public String getUseYn() {
			return useYn;
		}

		/** * @param 파라미터 useYn를 변수 useYn에 설정한다. */		
		public void setUseYn(String useYn) {
			this.useYn = useYn;
		}
}
