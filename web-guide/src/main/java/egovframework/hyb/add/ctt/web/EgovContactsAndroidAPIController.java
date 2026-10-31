package egovframework.hyb.add.ctt.web;

import java.io.IOException;
import java.util.List;

import javax.annotation.Resource;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import egovframework.hyb.add.ctt.service.ContactsAndroidAPIVO;
import egovframework.hyb.add.ctt.service.ContactsAndroidAPIVOList;
import egovframework.hyb.add.ctt.service.EgovContactsAndroidAPIService;
import egovframework.rte.fdl.cmmn.exception.BaseRuntimeException;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**  
 * @Class Name : EgovContactsAndroidAPIController.java
 * @Description : EgovContactsAndroidAPIController
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.08.13.  나신일              최초생성
 *   2020.08.14   신용호              Swagger 적용
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 8. 13
 * @version 1.0
 * @see
 * 
 */
@Controller
public class EgovContactsAndroidAPIController {

	// json-lib의 JSONObject.toBean은 알 수 없는 속성을 무시하므로 동일하게 관대하게 둔다.
	private static final ObjectMapper MAPPER = new ObjectMapper()
			.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

	/** EgovContactsAndroidAPIService */
	@Resource(name = "egovContactsAndroidAPIService")
	private EgovContactsAndroidAPIService egovContactsAndroidAPIService;

	/**
	 * 연락처 정보 목록을 조회한다.
	 * 
	 * @param contactVO
	 *            - 조회할 정보가 담긴 ContactsAndroidAPIVO
	 * @return ContactsAndroidAPIVOList
	 * @exception Exception
	 */
    @ApiOperation(value="연락처 정보 목록조회", notes="[Android] 연락처 정보 목록을 조회한다.", response=ContactsAndroidAPIVO.class, responseContainer="List")
    @ApiImplicitParams({
    	@ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
    })
	@SuppressWarnings("unchecked")
	@RequestMapping("/ctt/xml/contactsInfoList.do")
	public @ResponseBody
	ContactsAndroidAPIVOList selectContactsInfoListXml(ContactsAndroidAPIVO contactVO) throws Exception {

		List<ContactsAndroidAPIVO> contactInfoList = (List<ContactsAndroidAPIVO>) egovContactsAndroidAPIService.selectContactsInfoList(contactVO);

		ContactsAndroidAPIVOList contactsAndroidAPIVOList = new ContactsAndroidAPIVOList();

		contactsAndroidAPIVOList.setContactsInfoList(contactInfoList);

		return contactsAndroidAPIVOList;
	}

	/**
	 * 연락처 정보 Backup 을 요청 한다.
	 * 
	 * @param contactVO
	 *            - 연락처 정보가 담긴 ContactsAndroidAPIVO
	 * @return ContactsAndroidAPIVO
	 * @exception Exception
	 */
    @ApiOperation(value="연락처 정보 Backup 요청", notes="[Android] 연락처 정보 Backup을 요청한다.\nresponseOK = {\"resultState\",\"OK\"}")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "contactsList", value = "연락처 리스트", required = true, dataType = "string", paramType = "query")
    })
	@RequestMapping("/ctt/xml/addContactsInfo.do")
	public @ResponseBody
	ContactsAndroidAPIVO addContactsInfoXml(ContactsAndroidAPIVO contactVO) throws Exception {

		JsonNode jsonArray;
		try {
			jsonArray = MAPPER.readTree(contactVO.getContactsList().replaceAll("&quot;", "\"")).get("contactsList");
		} catch (IOException e) {
			throw new BaseRuntimeException(e);
		}
		if (jsonArray == null || !jsonArray.isArray()) {
			throw new BaseRuntimeException("contactsList가 없습니다.");
		}

		int nGetCount = jsonArray.size();

		ContactsAndroidAPIVO inputVO = null, selectVO = null;
		for (int i = 0; i < nGetCount; i++) {
			try {
				inputVO = MAPPER.treeToValue(jsonArray.get(i), ContactsAndroidAPIVO.class);
			} catch (IOException e) {
				throw new BaseRuntimeException(e);
			}
			selectVO = egovContactsAndroidAPIService.selectContactsInfo(inputVO);
			if (selectVO != null) {
				inputVO.setNewId(selectVO.getContactId());
				egovContactsAndroidAPIService.updateContactsInfo(inputVO);
			} else {
				egovContactsAndroidAPIService.insertContactsInfo(inputVO);
			}
		}

		int nCount = egovContactsAndroidAPIService.selectContactsCount(inputVO);

		ContactsAndroidAPIVO contactsAndroidAPIVO = new ContactsAndroidAPIVO();

		if (nCount > 0) {
			String strCount = String.valueOf(nCount);

			contactsAndroidAPIVO.setTotCount(nCount);
			contactsAndroidAPIVO.setResultState("OK");
			contactsAndroidAPIVO.setResultMessage(strCount + "개의 연락처가 백업되었습니다.");
		} else {
			contactsAndroidAPIVO.setResultState("FAIL");
			contactsAndroidAPIVO.setResultMessage("백업에 실패하였습니다.");
		}

		return contactsAndroidAPIVO;
	}

	/**
	 * 연락처 정보의 id를 update 한다.
	 * 
	 * @param contactVO
	 *            - 연락처 정보가 담긴 ContactsAndroidAPIVO
	 * @return ContactsAndroidAPIVO
	 * @exception Exception
	 */
    @ApiOperation(value="연락처 세부정보 수정", notes="[Android] 연락처 세부정보를 등록한다.\nresponseOK = {\"resultState\",\"OK\"}")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "contactsList", value = "연락처 리스트", required = true, dataType = "string", paramType = "query")
    })
	@RequestMapping("/ctt/xml/updateContacts.do")
	public @ResponseBody
	ContactsAndroidAPIVO updateContactsXml(ContactsAndroidAPIVO contactVO) throws Exception {

		JsonNode jsonArray;
		try {
			jsonArray = MAPPER.readTree(contactVO.getContactsList().replaceAll("&quot;", "\"")).get("contactsList");
		} catch (IOException e) {
			throw new BaseRuntimeException(e);
		}
		if (jsonArray == null || !jsonArray.isArray()) {
			throw new BaseRuntimeException("contactsList가 없습니다.");
		}

		int nGetCount = jsonArray.size();

		ContactsAndroidAPIVO inputVO = null, selectVO = null;;
		for (int i = 0; i < nGetCount; i++) {
			try {
				inputVO = MAPPER.treeToValue(jsonArray.get(i), ContactsAndroidAPIVO.class);
			} catch (IOException e) {
				throw new BaseRuntimeException(e);
			}
			selectVO = egovContactsAndroidAPIService.selectContactsInfo(inputVO);
			selectVO.setNewId(inputVO.getNewId());
			egovContactsAndroidAPIService.updateContactsInfo(selectVO);
		}

		int nCount = egovContactsAndroidAPIService.selectContactsCount(inputVO);

		ContactsAndroidAPIVO contactsAndroidAPIVO = new ContactsAndroidAPIVO();

		if (nGetCount > 0) {
			String strCount = String.valueOf(nGetCount);

			contactsAndroidAPIVO.setTotCount(nCount);
			contactsAndroidAPIVO.setResultState("OK");
			contactsAndroidAPIVO.setResultMessage(strCount);
		} else {
			contactsAndroidAPIVO.setResultState("FAIL");
			contactsAndroidAPIVO.setResultMessage("업데이트에 실패하였습니다.");
		}

		return contactsAndroidAPIVO;
	}

	/**
	 * 연락처 정보 삭제를 요청 한다.
	 * 
	 * @param contactVO
	 *            - 삭제할 정보가 담긴 ContactsAndroidAPIVO
	 * @return ContactsAndroidAPIVO
	 * @exception Exception
	 */
    @ApiOperation(value="연락처 세부정보 삭제", notes="[Android] 연락처 세부정보를 삭제한다.\nresponseOK = {\"resultState\",\"OK\"}")
    @ApiImplicitParams({
    	 @ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
         @ApiImplicitParam(name = "name", value = "연락처 이름", required = true, dataType = "string", paramType = "query"),
    	 @ApiImplicitParam(name = "telNo", value = "연락처 전화번호", required = true, dataType = "string", paramType = "query")
    })
	@RequestMapping("/ctt/xml/deleteContacts.do")
	public @ResponseBody
	ContactsAndroidAPIVO deleteContactsXml(ContactsAndroidAPIVO contactVO) throws Exception {

		ContactsAndroidAPIVO contactsAndroidAPIVO = new ContactsAndroidAPIVO();

		int nCount = egovContactsAndroidAPIService.deleteContactsInfo(contactVO);

		if (nCount > 0) {
			contactsAndroidAPIVO.setResultState("OK");
			contactsAndroidAPIVO.setResultMessage("삭제에 성공하였습니다.");
		} else {
			contactsAndroidAPIVO.setResultState("FAIL");
			contactsAndroidAPIVO.setResultMessage("삭제에 실패하였습니다.");
		}

		return contactsAndroidAPIVO;
	}

	/**
	 * 백업된 연락처 총 개수를 조회한다.
	 * 
	 * @param fileVO
	 *            - 조회할 정보가 담긴 ContactsAndroidAPIVO
	 * @return ContactsAndroidAPIVOList
	 * @exception Exception
	 */
    @ApiOperation(value="백업된 연락처 총 개수 조회", notes="[Android] 백업된 연락처 총 개수를 조회한다.", response=ContactsAndroidAPIVO.class)
    @ApiImplicitParams({
    	@ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
    })
	@RequestMapping("/ctt/xml/selectBackupCount.do")
	public @ResponseBody
	ContactsAndroidAPIVO selectContactsCountXml(ContactsAndroidAPIVO fileVO) throws Exception {

		int nCount = egovContactsAndroidAPIService.selectContactsCount(fileVO);

		ContactsAndroidAPIVO contactsAndroidAPIVO = new ContactsAndroidAPIVO();
		contactsAndroidAPIVO.setTotCount(nCount);
		contactsAndroidAPIVO.setResultState("OK");

		return contactsAndroidAPIVO;
	}
}
