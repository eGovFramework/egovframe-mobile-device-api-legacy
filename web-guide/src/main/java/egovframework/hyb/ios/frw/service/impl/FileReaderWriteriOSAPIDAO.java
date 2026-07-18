/**
 * 
 */
package egovframework.hyb.ios.frw.service.impl;

import java.util.List;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.ios.frw.service.FileReaderWriteriOSAPIVO;

import org.springframework.stereotype.Repository;

/**  
 * @Class Name : FileReaderWriteriOSAPIDAO.java
 * @Description : FileReaderWriteriOSAPIDAO
 * @
 * @  수정일                 수정자                 수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2012. 7. 10.  서준식                  최초생성
 * @ 2026. 6. 26.  이백행                  [2026년 컨트리뷰션] 불필요한 예외 제거
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 7. 10.
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */
@Repository("fileReaderWriteriOSAPIDAO")
public class FileReaderWriteriOSAPIDAO extends EgovComAbstractDAO{

	
	/**
	 * 파일  정보를 입력한다.
	 * @param fileVO - 파일 정보가 담긴 FileReaderWriteriOSAPIVO 
	 */
    public void insertFileInfo(FileReaderWriteriOSAPIVO vo) {
        insert("fileReaderWriteriOSAPIDAO.insertFileInfo", vo);
    }
    
    
    /**
	 * 업로드 된 파일의 상세 정보를 저장한다.
	 * @param fileVO - 파일 정보가 담긴 FileReaderWriteriOSAPIVO 
	 */
    public void insertFileDetailInfo(FileReaderWriteriOSAPIVO vo) {
        insert("fileReaderWriteriOSAPIDAO.insertFileDetailInfo", vo);
    }
    
    /**
	 * 파일 정보리스트를 조회한다.
	 * @param fileVO - 파일 정보가 담긴 FileReaderWriteriOSAPIVO 
	 */
    public List<?> selectFileInfoList(FileReaderWriteriOSAPIVO vo) {
    	return selectList("fileReaderWriteriOSAPIDAO.selectFileInfoList", vo);
    }
    
    /**
	 * 파일 정보를 조회한다.
	 * @param fileVO - 파일 정보가 담긴 FileReaderWriteriOSAPIVO 
	 */
    public FileReaderWriteriOSAPIVO selectFileInfo(FileReaderWriteriOSAPIVO vo) {
    	return (FileReaderWriteriOSAPIVO) selectOne("fileReaderWriteriOSAPIDAO.selectFileInfo", vo);
    }
    
    /**
	 * 파일 정보를 삭제한다.
	 * @param fileVO - 파일 정보가 담긴 FileReaderWriteriOSAPIVO 
	 */
    public void deleteFileInfo(FileReaderWriteriOSAPIVO vo) {
    	delete("fileReaderWriteriOSAPIDAO.deleteFileInfo", vo);
    }
    
    
    /**
	 * 파일 디테일 정보를 삭제한다.
	 * @param fileVO - 파일 정보가 담긴 FileReaderWriteriOSAPIVO 
	 */
    public void deleteFileDetailInfo(FileReaderWriteriOSAPIVO vo) {
    	delete("fileReaderWriteriOSAPIDAO.deleteFileDetailInfo", vo);
    }
}
