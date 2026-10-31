package egovframework.hyb.add.frw.service.impl;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * EgovWebUtil.filePathBlackList 단위 테스트. 서버·DB 없이 동작한다.
 * 다른 모듈의 동명 클래스는 이 파일과 로직이 같고 패키지만 다르다.
 */
public class EgovWebUtilTest {

    @Test
    // 공식 패치는 ".." 문자열만 지운다(슬래시는 남는다).
    public void 상위경로_이동은_제거된다() {
        assertEquals("//file.txt", EgovWebUtil.filePathBlackList("../../file.txt"));
        assertEquals("/upload///file.txt", EgovWebUtil.filePathBlackList("/upload/../../file.txt"));
    }

    @Test
    public void 정상_경로는_그대로이다() {
        assertEquals("/upload/2024/file.txt", EgovWebUtil.filePathBlackList("/upload/2024/file.txt"));
    }

    @Test
    public void 비어있으면_빈문자열이다() {
        assertEquals("", EgovWebUtil.filePathBlackList(null));
        assertEquals("", EgovWebUtil.filePathBlackList("   "));
    }
    @Test
    public void 기본경로_결합형도_상위이동을_제거한다() {
        assertEquals("/upload//file.txt", EgovWebUtil.filePathBlackList("../file.txt", "/upload/"));
    }

    @Test(expected = SecurityException.class)
    public void 기본경로가_없으면_거부한다() {
        EgovWebUtil.filePathBlackList("file.txt", "");
    }

    @Test(expected = SecurityException.class)
    public void 루트를_기본경로로_쓰면_거부한다() {
        EgovWebUtil.filePathBlackList("file.txt", "/");
    }
}
