package egovframework.hyb.mbl.stm.service;

import java.util.List;

import javax.servlet.http.HttpServletResponse;

/**  
 * @Class Name : EgovStreamingMediaAPIService.java
 * @Description : EgovStreamingMediaAPIService Class
 * @Modification Information  
 * @
 * @  수정일            수정자        수정내용
 * @ ---------        ---------    -------------------------------
 * @ 2016. 7. 14.     장성호        최초생성
 * 
 * @author 디바이스 API 실행환경 팀
 * @since 2016. 7. 14.
 * @version 1.0
 * @see
 * 
 */
public interface EgovStreamingMediaAPIService {

    /**
     * 미디어 목록을 조회한다.
     * @param VO - 조회할 정보가 담긴 MediaAndroidAPIVO
     * @return 조회 목록
     * @exception Exception
     */
    public List<?> selectMediaInfoList(StreamingMediaAPIDefaultVO vo) throws Exception;
    
    
    /**
     * 미디어 파일을 조회한다.
     * @param VO - 조회할 정보가 담긴 MediaAndroidAPIFileVO
     * @return 파일 정보
     * @exception Exception
     */
    public boolean selectMediaFileInf(HttpServletResponse response, StreamingMediaAPIFileVO vo) throws Exception;

    
	public StreamingMediaAPIFileVO selectMediaFileURL(StreamingMediaAPIFileVO vo) throws Exception;
    
    public int updateMediaInfoRevivCo(StreamingMediaAPIVO vo) throws Exception;
}
