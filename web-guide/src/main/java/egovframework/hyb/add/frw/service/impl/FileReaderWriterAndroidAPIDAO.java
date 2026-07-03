/**
 * 
 */
package egovframework.hyb.add.frw.service.impl;

import java.util.List;

import org.springframework.stereotype.Repository;

import egovframework.com.cmm.mapper.EgovComAbstractDAO;
import egovframework.hyb.add.frw.service.FileReaderWriterAndroidAPIVO;

/**  
 * @Class Name : FileReaderWriterAndroidAPIDAO.java
 * @Description : FileReaderWriterAndroidAPIDAO
 * @
 * @  수정일                 수정자                 수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2012. 8. 6.  나신일                   최초생성
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 8. 6
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */
@Repository("fileReaderWriterAndroidAPIDAO")
public class FileReaderWriterAndroidAPIDAO extends EgovComAbstractDAO {

    /**
     * 파일 정보를 입력한다.
     * 
     * @param fileVO
     *            - 파일 정보가 담긴 FileReaderWriterAndroidAPIVO
     * @exception Exception
     */
    public void insertFileInfo(FileReaderWriterAndroidAPIVO vo)
            throws Exception {
        insert("fileReaderWriterAndroidAPIDAO.insertFileInfo", vo);
    }

    /**
     * 업로드 된 파일의 상세 정보를 저장한다.
     * 
     * @param fileVO
     *            - 파일 정보가 담긴 FileReaderWriterAndroidAPIVO
     * @exception Exception
     */
    public void insertFileDetailInfo(FileReaderWriterAndroidAPIVO vo)
            throws Exception {
        insert("fileReaderWriterAndroidAPIDAO.insertFileDetailInfo", vo);
    }

    /**
     * 파일 정보리스트를 조회한다.
     * 
     * @param fileVO
     *            - 파일 정보가 담긴 FileReaderWriterAndroidAPIVO
     * @exception Exception
     */
    public List<?> selectFileInfoList(FileReaderWriterAndroidAPIVO vo)
            throws Exception {
        return selectList("fileReaderWriterAndroidAPIDAO.selectFileInfoList", vo);
    }

    /**
     * 파일 정보를 조회한다.
     * 
     * @param fileVO
     *            - 파일 정보가 담긴 FileReaderWriterAndroidAPIVO
     * @exception Exception
     */
    public FileReaderWriterAndroidAPIVO selectFileInfo(
            FileReaderWriterAndroidAPIVO vo) throws Exception {
        return (FileReaderWriterAndroidAPIVO) selectOne(
                "fileReaderWriterAndroidAPIDAO.selectFileInfo", vo);
    }

    /**
     * 파일 정보를 삭제한다.
     * 
     * @param fileVO
     *            - 파일 정보가 담긴 FileReaderWriterAndroidAPIVO
     * @exception Exception
     */
    public int deleteFileInfo(FileReaderWriterAndroidAPIVO vo) throws Exception {
        return delete("fileReaderWriterAndroidAPIDAO.deleteFileInfo", vo);
    }

    /**
     * 파일 디테일 정보를 삭제한다.
     * 
     * @param fileVO
     *            - 파일 정보가 담긴 FileReaderWriterAndroidAPIVO
     * @exception Exception
     */
    public int deleteFileDetailInfo(FileReaderWriterAndroidAPIVO vo)
            throws Exception {
        return delete("fileReaderWriterAndroidAPIDAO.deleteFileDetailInfo", vo);
    }
}
