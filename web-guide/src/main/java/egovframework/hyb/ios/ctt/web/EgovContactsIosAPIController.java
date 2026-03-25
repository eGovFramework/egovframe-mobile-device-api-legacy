package egovframework.hyb.ios.ctt.web;

import java.util.List;

import egovframework.hyb.add.ctt.service.ContactsAndroidAPIVO;
import egovframework.hyb.ios.ctt.service.ContactsiOSAPIVO;
import egovframework.hyb.ios.ctt.service.EgovContactsiOSAPIService;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;

import javax.annotation.Resource;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

/**  
 * @Class Name : EgovContactsiOSAPIController.java
 * @Description : EgovContactsiOSAPIController
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.08.13   나신일              최초생성
 *   2012.08.23   이해성              커스터마이징
 *   2020.08.14   신용호              Swagger 적용
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2012. 8. 13
 * @version 1.0
 * @see
 * 
 */
@Controller
public class EgovContactsIosAPIController {
	
	/** EgovContactsiOSAPIService */
	@Resource(name="egovContactsiOSAPIService")
	private EgovContactsiOSAPIService egovContactsiOSAPIService;
	
	/**
	 * 연락처  정보 목록을 조회한다.
	 * @param contactVO - 조회할 정보가 담긴 ContactsiOSAPIVO 
	 * @return ContactsiOSAPIVOList
	 * @exception Exception
	 */
    @ApiOperation(value="연락처 정보 목록조회", notes="[iOS] 연락처 정보 목록을 조회한다.", response=ContactsAndroidAPIVO.class, responseContainer="List")
    @ApiImplicitParams({
    	@ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
    })
	@SuppressWarnings("unchecked")
	@RequestMapping("/ctt/contactsiOSInfoList.do")
	public ModelAndView selectContactsInfoListXml(ContactsiOSAPIVO contactVO) throws Exception{
		
		List<ContactsiOSAPIVO> contactInfoList = (List<ContactsiOSAPIVO>) egovContactsiOSAPIService.selectContactsInfoList(contactVO);
		
		ModelAndView jsonView = new ModelAndView("jsonView");
		jsonView.addObject("contactInfoList", contactInfoList);
		jsonView.addObject("resultState","OK");
		
		return jsonView;
	}
	
	
	/**
	 * 연락처  정보 Backup 을 요청 한다.
	 * @param contactVO - 연락처 정보가 담긴 ContactsiOSAPIVO 
	 * @return ContactsiOSAPIVO
	 * @exception Exception
	 */
    @ApiOperation(value="연락처 정보 Backup 요청", notes="[iOS] 연락처 정보 Backup을 요청한다.\nresponseOK = {\"resultState\",\"OK\"}")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "contactsList", value = "연락처 리스트", required = true, dataType = "string", paramType = "query")
    })
	@RequestMapping("/ctt/addContactsiOSInfo.do")
	public @ResponseBody ContactsiOSAPIVO addContactsInfoXml(ContactsiOSAPIVO contactVO) throws Exception{
		String makeJSONString = contactVO.getContactsList().replaceAll("&quot;", "\"");
		String decodeName = java.net.URLDecoder.decode(makeJSONString,"utf-8");
		JSONObject jsonObject = JSONObject.fromObject(decodeName);
		JSONArray jsonArray = jsonObject.getJSONArray("contactsList");
		
		int nGetCount = jsonArray.size();
		ContactsiOSAPIVO inputVO = null, selectVO = null;
		for(int i = 0 ; i < nGetCount ; i++) {
			inputVO = (ContactsiOSAPIVO) JSONObject.toBean((JSONObject)jsonArray.get(i), ContactsiOSAPIVO.class);
			selectVO = egovContactsiOSAPIService.selectContactsInfo(inputVO);
			if(selectVO != null) {
				inputVO.setNewId(selectVO.getContactId());
				egovContactsiOSAPIService.updateContactsInfo(inputVO);
			} else {
				egovContactsiOSAPIService.insertContactsInfo(inputVO);
			}
		}
		
		int nCount = egovContactsiOSAPIService.selectContactsCount(inputVO);

		ContactsiOSAPIVO contactsiOSAPIVO = new ContactsiOSAPIVO();
		
		if(nCount > 0) {
			String strCount = String.valueOf(nCount);
			
			contactsiOSAPIVO.setTotCount(nCount);
			contactsiOSAPIVO.setResultState("OK");
			contactsiOSAPIVO.setResultMessage(strCount + "개의 연락처가 백업되었습니다.");
    	} else {
    		contactsiOSAPIVO.setResultState("FAIL");
    		contactsiOSAPIVO.setResultMessage("백업에 실패하였습니다.");
    	}

		return contactsiOSAPIVO;
	}
	
	/**
	 * 연락처  정보의 id를 update 한다.
	 * @param contactVO - 연락처 정보가 담긴 ContactsiOSAPIVO 
	 * @return ContactsiOSAPIVO
	 * @exception Exception
	 */
    @ApiOperation(value="연락처 세부정보 수정", notes="[Android] 연락처 세부정보를 등록한다.\nresponseOK = {\"resultState\",\"OK\"}")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "contactsList", value = "연락처 리스트", required = true, dataType = "string", paramType = "query")
    })
	@RequestMapping("/ctt/updateContactsiOS.do")
	public @ResponseBody ContactsiOSAPIVO updateContactsiOS(ContactsiOSAPIVO contactVO) throws Exception{
		String makeJSONString = contactVO.getContactsList().replaceAll("&quot;", "\"");
		
		JSONObject jsonObject = JSONObject.fromObject(makeJSONString);
		JSONArray jsonArray = jsonObject.getJSONArray("contactsList");
		
		int nGetCount = jsonArray.size();
		
		ContactsiOSAPIVO inputVO = null, selectVO = null;;		
		for(int i = 0 ; i < nGetCount ; i++) {
			inputVO = (ContactsiOSAPIVO) JSONObject.toBean((JSONObject)jsonArray.get(i), ContactsiOSAPIVO.class);
			selectVO = egovContactsiOSAPIService.selectContactsInfo(inputVO);
			selectVO.setNewId(inputVO.getNewId());
			egovContactsiOSAPIService.updateContactsInfo(selectVO);
		}
		
		int nCount = egovContactsiOSAPIService.selectContactsCount(inputVO);

		ContactsiOSAPIVO contactsiOSAPIVO = new ContactsiOSAPIVO();
		
		if(nGetCount > 0) {
			String strCount = String.valueOf(nGetCount);
			
			contactsiOSAPIVO.setTotCount(nCount);
			contactsiOSAPIVO.setResultState("OK");
			contactsiOSAPIVO.setResultMessage(strCount);
    	} else {
    		contactsiOSAPIVO.setResultState("FAIL");
    		contactsiOSAPIVO.setResultMessage("업데이트에 실패하였습니다.");
    	}
		
		return contactsiOSAPIVO;
	}
	
	/**
	 * 연락처  정보  삭제를 요청 한다.
	 * @param contactVO - 삭제할 정보가 담긴 ContactsiOSAPIVO 
	 * @return ContactsiOSAPIVO
	 * @exception Exception
	 */
    @ApiOperation(value="연락처 세부정보 삭제", notes="[iOS] 연락처 세부정보를 삭제한다.\nresponseOK = {\"resultState\",\"OK\"}")
    @ApiImplicitParams({
    	 @ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
         @ApiImplicitParam(name = "name", value = "연락처 이름", required = true, dataType = "string", paramType = "query"),
    	 @ApiImplicitParam(name = "telNo", value = "연락처 전화번호", required = true, dataType = "string", paramType = "query")
    })
	@RequestMapping("/ctt/deleteContactsiOS.do")
	public @ResponseBody ContactsiOSAPIVO deleteContactsiOS(ContactsiOSAPIVO contactVO) throws Exception{
		
		ContactsiOSAPIVO contactsiOSAPIVO = new ContactsiOSAPIVO();
		
		int nCount = egovContactsiOSAPIService.deleteContactsInfo(contactVO);	
		
		if(nCount > 0) {
			contactsiOSAPIVO.setResultState("OK");
			contactsiOSAPIVO.setResultMessage("삭제에 성공하였습니다.");	    	
		} else {
			contactsiOSAPIVO.setResultState("FAIL");
			contactsiOSAPIVO.setResultMessage("삭제에 실패하였습니다.");
    	}
		
		return contactsiOSAPIVO;
	}
	
	/**
	 * 백업된 연락처  총 개수를 조회한다.
	 * @param fileVO - 조회할 정보가 담긴 ContactsiOSAPIVO 
	 * @return ContactsiOSAPIVOList
	 * @exception Exception
	 */
    @ApiOperation(value="백업된 연락처 총 개수 조회", notes="[iOS] 백업된 연락처 총 개수를 조회한다.", response=ContactsAndroidAPIVO.class)
    @ApiImplicitParams({
    	@ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
    })
	@RequestMapping("/ctt/selectBackupCountiOS.do")
	public @ResponseBody ContactsiOSAPIVO selectContactsCount(ContactsiOSAPIVO fileVO) throws Exception{
		int nCount = egovContactsiOSAPIService.selectContactsCount(fileVO);
		ContactsiOSAPIVO contactsiOSAPIVO  = new ContactsiOSAPIVO();
		contactsiOSAPIVO.setTotCount(nCount);
		contactsiOSAPIVO.setResultState("OK");
		return contactsiOSAPIVO;
	}
}

