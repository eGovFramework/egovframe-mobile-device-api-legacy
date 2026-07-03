package egovframework.hyb.mbl.stm.service;

import java.io.Serializable;

/**  
 * @Class Name : StreamingMediaAPIFileVO.java
 * @Description : StreamingMediaAPIFileVO Class
 * @Modification Information  
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------   ---------   -------------------------------
 *   2016.07.14   장성호             최초생성
 *   2020.09.16   신용호             Swagger 적용
 * 
 * @author 디바이스 API 실행환경 팀
 * @since 2016. 7. 14.
 * @version 1.0
 * @see
 * 
 */
public class StreamingMediaAPIFileVO implements Serializable {

	private static final long serialVersionUID = 1L;
	
    /** 미디어 일련번호 */
	    private int sn;
    
    /** 파일연번 */
	    private int fileSn;
    
    /** 파일저장경로 */
	    private String fileStreCours;
    
    /** 저장파일명 */
	    private String streFileNm;
    
    /** 원파일명 */
	    private String orignlFileNm;
    
    /** 파일확장자 */
	    private String fileExtsn;
    
    /** 파일내용 */
	    private String fileCn;
    
    /** 파일크기 */
	    private String fileSize;
    
    /** 미디어 구분 코드 */
	    private String mdCode;
    
    /** 미디어 제목 */
	    private String mdSj;
    
    /** 디바이스 식별 */
	    private String uuid;
    
    /** 활성화여부 */
	    private String useyn;
    
    /** 재생 횟수 */
	    private String revivCo;

    /**
     * @return sn을 반환한다.
     */
    public int getSn() {
        return sn;
    }

    /**
     * @param 파라미터 sn을 sn에 설정한다.
     */
    public void setSn(int sn) {
        this.sn = sn;
    }

    /**
     * @return fileSn을 반환한다.
     */
    public int getFileSn() {
        return fileSn;
    }

    /**
     * @param 파라미터 fileSn을 fileSn에 설정한다.
     */
    public void setFileSn(int fileSn) {
        this.fileSn = fileSn;
    }

    /**
     * @return fileStreCours을 반환한다.
     */
    public String getFileStreCours() {
        return fileStreCours;
    }

    /**
     * @param 파라미터 fileStreCours을 fileStreCours에 설정한다.
     */
    public void setFileStreCours(String fileStreCours) {
        this.fileStreCours = fileStreCours;
    }

    /**
     * @return streFileNm을 반환한다.
     */
    public String getStreFileNm() {
        return streFileNm;
    }

    /**
     * @param 파라미터 streFileNm을 streFileNm에 설정한다.
     */
    public void setStreFileNm(String streFileNm) {
        this.streFileNm = streFileNm;
    }

    /**
     * @return orignlFileNm을 반환한다.
     */
    public String getOrignlFileNm() {
        return orignlFileNm;
    }

    /**
     * @param 파라미터 orignlFileNm을 orignlFileNm에 설정한다.
     */
    public void setOrignlFileNm(String orignlFileNm) {
        this.orignlFileNm = orignlFileNm;
    }

    /**
     * @return fileExtsn을 반환한다.
     */
    public String getFileExtsn() {
        return fileExtsn;
    }

    /**
     * @param 파라미터 fileExtsn을 fileExtsn에 설정한다.
     */
    public void setFileExtsn(String fileExtsn) {
        this.fileExtsn = fileExtsn;
    }

    /**
     * @return fileCn을 반환한다.
     */
    public String getFileCn() {
        return fileCn;
    }

    /**
     * @param 파라미터 fileCn을 fileCn에 설정한다.
     */
    public void setFileCn(String fileCn) {
        this.fileCn = fileCn;
    }

    /**
     * @return fileSize을 반환한다.
     */
    public String getFileSize() {
        return fileSize;
    }

    /**
     * @param 파라미터 fileSize을 fileSize에 설정한다.
     */
    public void setFileSize(String fileSize) {
        this.fileSize = fileSize;
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
