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
	 * @exception Exception
	 */
    public void insertContactsInfo(ContactsiOSAPIVO vo) throws Exception {
        insert("contactsiOSAPIDAO.insertContactInfo", vo);
    }
    
    
    /**
	 * 연락처 정보를 업데이트 한다.
	 * @param vo - 연락처 정보가 담긴 ContactsiOSAPIVO 
	 * @exception Exception
	 */
    public void updateContactsInfo(ContactsiOSAPIVO vo) throws Exception {
        insert("contactsiOSAPIDAO.updateContactInfo", vo);
    }
    
    /**
	 * 연락처 정보리스트를 조회한다.
	 * @param vo - 연락처 정보가 담긴 ContactsiOSAPIVO 
	 * @exception Exception
	 */
    public List<?> selectFileInfoList(ContactsiOSAPIVO vo) throws Exception{
    	return selectList("contactsiOSAPIDAO.selectContactInfoList", vo);
    }
    
    /**
	 * 연락처 정보를 조회한다.
	 * @param vo - 연락처 정보가 담긴 ContactsiOSAPIVO 
	 * @exception Exception
	 */
    public ContactsiOSAPIVO selectContactsInfo(ContactsiOSAPIVO vo) throws Exception{
    	return (ContactsiOSAPIVO) selectOne("contactsiOSAPIDAO.selectContactInfo", vo);
    }
    
    /**
	 * 연락처 정보를 삭제한다.
	 * @param vo - 연락처 정보가 담긴 ContactsiOSAPIVO 
	 * @exception Exception
	 */
    public int deleteContactsInfo(ContactsiOSAPIVO vo) throws Exception {
    	return delete("contactsiOSAPIDAO.deleteContactInfo", vo);
    }
    
    /**
	 * 연락처 정보를 삭제한다.
	 * @param vo - 연락처 정보가 담긴 ContactsiOSAPIVO 
	 * @exception Exception
	 */
    public int selectContactsTotCnt(ContactsiOSAPIVO vo) throws Exception {
    	return (Integer) selectOne("contactsiOSAPIDAO.selectContactInfoListTotCnt", vo);    	
    }
}
