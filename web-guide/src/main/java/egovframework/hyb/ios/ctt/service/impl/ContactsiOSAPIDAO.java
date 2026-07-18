/**
 * 
 */
package egovframework.hyb.ios.ctt.service.impl;

import java.util.List;

import org.springframework.stereotype.Repository;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.ios.ctt.service.ContactsiOSAPIVO;

/**  
 * @Class Name : ContactsiOSAPIDAO.java
 * @Description : ContactsiOSAPIDAO
 * @
 * @  수정일                 수정자                 수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2012. 8. 13.  나신일                   최초생성
 * @ 2012. 8. 23.  이해성                   커스터마이징
 *   2026.06.26    이백행                  [2026년 컨트리뷰션] 불필요한 예외 제거
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 8. 13
 * @version 1.0
 * @see
 * 
 */
@Repository("contactsiOSAPIDAO")
public class ContactsiOSAPIDAO extends EgovComAbstractDAO{

	
	/**
	 * 연락처  정보를 입력한다.
	 * @param vo - 연락처 정보가 담긴 ContactsiOSAPIVO 
	 */
    public void insertContactsInfo(ContactsiOSAPIVO vo) {
        insert("contactsiOSAPIDAO.insertContactInfo", vo);
    }
    
    
    /**
	 * 연락처 정보를 업데이트 한다.
	 * @param vo - 연락처 정보가 담긴 ContactsiOSAPIVO 
	 */
    public void updateContactsInfo(ContactsiOSAPIVO vo) {
        insert("contactsiOSAPIDAO.updateContactInfo", vo);
    }
    
    /**
	 * 연락처 정보리스트를 조회한다.
	 * @param vo - 연락처 정보가 담긴 ContactsiOSAPIVO 
	 */
    public List<?> selectFileInfoList(ContactsiOSAPIVO vo) {
    	return selectList("contactsiOSAPIDAO.selectContactInfoList", vo);
    }
    
    /**
	 * 연락처 정보를 조회한다.
	 * @param vo - 연락처 정보가 담긴 ContactsiOSAPIVO 
	 */
    public ContactsiOSAPIVO selectContactsInfo(ContactsiOSAPIVO vo) {
    	return (ContactsiOSAPIVO) selectOne("contactsiOSAPIDAO.selectContactInfo", vo);
    }
    
    /**
	 * 연락처 정보를 삭제한다.
	 * @param vo - 연락처 정보가 담긴 ContactsiOSAPIVO 
	 */
    public int deleteContactsInfo(ContactsiOSAPIVO vo) {
    	return delete("contactsiOSAPIDAO.deleteContactInfo", vo);
    }
    
    /**
	 * 연락처 정보를 삭제한다.
	 * @param vo - 연락처 정보가 담긴 ContactsiOSAPIVO 
	 */
    public int selectContactsTotCnt(ContactsiOSAPIVO vo) {
    	return (Integer) selectOne("contactsiOSAPIDAO.selectContactInfoListTotCnt", vo);    	
    }
}
