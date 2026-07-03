/**
 * 
 */
package egovframework.hyb.add.frw.service;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**  
 * @Class Name : FileReaderWriterAndroidAPIVO.java
 * @Description : FileReaderWriterAndroidAPIVO
 * @
 * @ 수정일                수정자             수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.08.06   나신일             최초생성
 *   2020.07.29   신용호             Swagger 적용
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 8. 6
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

@XmlRootElement
public class FileReaderWriterAndroidAPIVO {

    /** 일련번호 */
	    private int sn;

    /** UUID(기기식별코드) */
	    private String uuid;

    /** 파일 일련번호 */
	    private int fileSn;

    /** 파일 이름 */
	    private String fileNm;

    /** 파일 타입 */
	    private String fileType;

    /** 수정일 */
	    private String updtDt;

    /** 사용 여부 */
	    private String useYn;

    /** 파일 저장 경로 */
	    private String fileStreCours;

    /** 저장된 파일 이름 */
	    private String streFileNm;

    /** 원 파일 이름 */
	    private String orignlFileNm;

    /** 파일 확장자 명 */
	    private String fileExtsn;

    /** 파일 내용 */
	    private String fileCn;

    /** 파일 사이즈 */
	    private String fileSize;

    /** resultState */
	    private String resultState;

    /** resultMessage */
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
     * @return fileSn을 반환한다
     */
    public int getFileSn() {
        return fileSn;
    }

    /**
     * @param 파라미터
     *            fileSn를 변수 fileSn에 설정한다.
     */
    @XmlElement
    public void setFileSn(int fileSn) {
        this.fileSn = fileSn;
    }

    /**
     * @return fileNm을 반환한다
     */
    public String getFileNm() {
        return fileNm;
    }

    /**
     * @param 파라미터
     *            fileNm를 변수 fileNm에 설정한다.
     */
    @XmlElement
    public void setFileNm(String fileNm) {
        this.fileNm = fileNm;
    }

    /**
     * @return fileType을 반환한다
     */
    public String getFileType() {
        return fileType;
    }

    /**
     * @param 파라미터
     *            fileType를 변수 fileType에 설정한다.
     */
    @XmlElement
    public void setFileType(String fileType) {
        this.fileType = fileType;
    }

    /**
     * @return updtDt을 반환한다
     */
    public String getUpdtDt() {
        return updtDt;
    }

    /**
     * @param 파라미터
     *            updtDt를 변수 updtDt에 설정한다.
     */
    @XmlElement
    public void setUpdtDt(String updtDt) {
        this.updtDt = updtDt;
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
    public void setUseYn(String useYn) {
        this.useYn = useYn;
    }

    /**
     * @return fileStreCours을 반환한다
     */
    public String getFileStreCours() {
        return fileStreCours;
    }

    /**
     * @param 파라미터
     *            fileStreCours를 변수 fileStreCours에 설정한다.
     */
    @XmlElement
    public void setFileStreCours(String fileStreCours) {
        this.fileStreCours = fileStreCours;
    }

    /**
     * @return streFileNm을 반환한다
     */
    public String getStreFileNm() {
        return streFileNm;
    }

    /**
     * @param 파라미터
     *            streFileNm를 변수 streFileNm에 설정한다.
     */
    @XmlElement
    public void setStreFileNm(String streFileNm) {
        this.streFileNm = streFileNm;
    }

    /**
     * @return orignlFileNm을 반환한다
     */
    public String getOrignlFileNm() {
        return orignlFileNm;
    }

    /**
     * @param 파라미터
     *            orignlFileNm를 변수 orignlFileNm에 설정한다.
     */
    @XmlElement
    public void setOrignlFileNm(String orignlFileNm) {
        this.orignlFileNm = orignlFileNm;
    }

    /**
     * @return fileExtsn을 반환한다
     */
    public String getFileExtsn() {
        return fileExtsn;
    }

    /**
     * @param 파라미터
     *            fileExtsn를 변수 fileExtsn에 설정한다.
     */
    @XmlElement
    public void setFileExtsn(String fileExtsn) {
        this.fileExtsn = fileExtsn;
    }

    /**
     * @return fileCn을 반환한다
     */
    public String getFileCn() {
        return fileCn;
    }

    /**
     * @param 파라미터
     *            fileCn를 변수 fileCn에 설정한다.
     */
    @XmlElement
    public void setFileCn(String fileCn) {
        this.fileCn = fileCn;
    }

    /**
     * @return fileSize을 반환한다
     */
    public String getFileSize() {
        return fileSize;
    }

    /**
     * @param 파라미터
     *            fileSize를 변수 fileSize에 설정한다.
     */
    @XmlElement
    public void setFileSize(String fileSize) {
        this.fileSize = fileSize;
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
    public void setResultState(String resultState) {
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
    public void setResultMessage(String resultMessage) {
        this.resultMessage = resultMessage;
    }
}
