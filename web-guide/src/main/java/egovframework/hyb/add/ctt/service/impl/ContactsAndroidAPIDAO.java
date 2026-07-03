/**
 * 
 */
package egovframework.hyb.add.ctt.service.impl;

import java.util.List;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.add.ctt.service.ContactsAndroidAPIVO;

import org.springframework.stereotype.Repository;

/**  
 * @Class Name : ContactsAndroidAPIDAO.java
 * @Description : ContactsAndroidAPIDAO
 * @
 * @  수정일                 수정자                 수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2012. 8. 13.  나신일                   최초생성
 * @ 2026. 6. 26.  이백행                   [2026년 컨트리뷰션] 불필요한 예외(throws Exception) 제거
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 8. 13
 * @version 1.0
 * @see
 * 
 */
@Repository("contactsAndroidAPIDAO")
public class ContactsAndroidAPIDAO extends EgovComAbstractDAO {

    /**
     * 연락처 정보를 입력한다.
     * 
     * @param vo
     *            - 연락처 정보가 담긴 ContactsAndroidAPIVO
     */
    public void insertContactsInfo(ContactsAndroidAPIVO vo) {
        insert("contactsAndroidAPIDAO.insertContactInfo", vo);
    }

    /**
     * 연락처 정보를 업데이트 한다.
     * 
     * @param vo
     *            - 연락처 정보가 담긴 ContactsAndroidAPIVO
     */
    public void updateContactsInfo(ContactsAndroidAPIVO vo) {
        insert("contactsAndroidAPIDAO.updateContactInfo", vo);
    }

    /**
     * 연락처 정보리스트를 조회한다.
     * 
     * @param vo
     *            - 연락처 정보가 담긴 ContactsAndroidAPIVO
     */
    public List<?> selectFileInfoList(ContactsAndroidAPIVO vo) {
        return selectList("contactsAndroidAPIDAO.selectContactInfoList", vo);
    }

    /**
     * 연락처 정보를 조회한다.
     * 
     * @param vo
     *            - 연락처 정보가 담긴 ContactsAndroidAPIVO
     */
    public ContactsAndroidAPIVO selectContactsInfo(ContactsAndroidAPIVO vo) {
        return (ContactsAndroidAPIVO) selectOne(
                "contactsAndroidAPIDAO.selectContactInfo", vo);
    }

    /**
     * 연락처 정보를 삭제한다.
     * 
     * @param vo
     *            - 연락처 정보가 담긴 ContactsAndroidAPIVO
     */
    public int deleteContactsInfo(ContactsAndroidAPIVO vo) {
        return delete("contactsAndroidAPIDAO.deleteContactInfo", vo);
    }

    /**
     * 연락처 정보를 삭제한다.
     * 
     * @param vo
     *            - 연락처 정보가 담긴 ContactsAndroidAPIVO
     */
    public int selectContactsTotCnt(ContactsAndroidAPIVO vo) {
        return (Integer) selectOne(
                "contactsAndroidAPIDAO.selectContactInfoListTotCnt", vo);
    }
}
