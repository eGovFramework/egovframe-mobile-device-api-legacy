/*
 * Copyright 2008-2009 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package egovframework.hyb.ios.itf.web;

import javax.annotation.Resource;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import egovframework.hyb.ios.itf.service.EgovInterfaceiOSAPIService;
import egovframework.hyb.ios.itf.service.InterfaceiOSAPIVO;
import egovframework.rte.fdl.property.EgovPropertyService;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;

/**  
 * @Class Name : EgovInterfaceiOSAPIController
 * @Description : EgovInterfaceiOSAPIController Controller Class
 * @Modification Information  
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------   ---------   -------------------------------
 *   2012.07.11   이한철             최초생성
 *   2020.09.02   신용호             Swagger 적용
 * 
 * 
 * @author 모바일 디바이스 API 팀
 * @since 2012. 07. 11
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOPAS All right reserved.
 */

@Controller
public class EgovInterfaceIosAPIController {

    /** EgovInterfaceAPIService */
    @Resource(name = "EgovInterfaceiOSAPIService")
    private EgovInterfaceiOSAPIService egovInterfaceAPIService;

    /** propertiesService */
    @Resource(name = "propertiesService")
    protected EgovPropertyService propertiesService;

    /**
     * 회원가입 정보를 등록한다.
     * 
     * @param searchVO
     *            - 등록할 정보가 담긴 InterfaceAPIDefaultVO
     * @param status
     * @return "forward:/itf/addInterfaceInfo.do"
     * @exception Exception
     */
    @ApiOperation(value="Interface 회원가입 정보 등록", notes="[iOS] 회원가입 정보를 등록한다", response=InterfaceiOSAPIVO.class)
    @ApiImplicitParams({
    	@ApiImplicitParam(name = "sn", value = "일련번호", required = true, dataType = "int", paramType = "query"),
    	@ApiImplicitParam(name = "uuid", value = "기기식별코드", required = true, dataType = "string", paramType = "query"),
    })
    @RequestMapping("/itf/addInterfaceiOSInfo.do")
    public ModelAndView addInterfaceInfo(
            InterfaceiOSAPIVO interfaceVO, BindingResult bindingResult,
            Model model, SessionStatus status) throws Exception {

        ModelAndView jsonView = new ModelAndView("jsonView");

        int cnt = egovInterfaceAPIService
                .selectInterfaceInfoListTotCnt(interfaceVO);

        if (cnt > 0) {
            jsonView.addObject("resultState", "FAIL");
            jsonView.addObject("resultMessage", "ID가 존재합니다.");
        } else {
            int success = egovInterfaceAPIService
                    .insertInterfaceInfo(interfaceVO);
            if (success > 0) {
                jsonView.addObject("resultState", "OK");
                jsonView.addObject("resultMessage", "가입에 성공하였습니다.");
            } else {
                jsonView.addObject("resultState", "FAIL");
                jsonView.addObject("resultMessage", "가입에 실패하였습니다.");
            }
        }

        return jsonView;
    }

    /**
     * 로그인을 한다.
     * 
     * @param interfaceVO
     *            - 로그인 할 정보가 담긴 InterfaceiOSAPIVO
     * @param status
     * @return "forward:/itf/logIn.do"
     * @exception Exception
     */
    @ApiOperation(value="Interface 로그인 조회", notes="[iOS] 로그인을 한다.", response=InterfaceiOSAPIVO.class)
    @ApiImplicitParams({
    	@ApiImplicitParam(name = "userId", value = "아이디", required = true, dataType = "string", paramType = "query"),
    	@ApiImplicitParam(name = "userPw", value = "비밀번호", required = true, dataType = "string", paramType = "query"),
    })
    @RequestMapping("/itf/logIniOS.do")
    public ModelAndView logIn(
            InterfaceiOSAPIVO interfaceVO, BindingResult bindingResult,
            Model model, SessionStatus status) throws Exception {

        ModelAndView jsonView = new ModelAndView("jsonView");

        InterfaceiOSAPIVO interfaceiOSAPIVO = null;
        interfaceiOSAPIVO = egovInterfaceAPIService
                .selectInterfaceInfo(interfaceVO);

        if (interfaceVO.getUserId().equals(interfaceiOSAPIVO.getUserId())) {
            jsonView.addObject("resultState", "OK");
            jsonView.addObject("resultMessage", "로그인에 성공하였습니다.");
        } else {
            jsonView.addObject("resultState", "FAIL");
            jsonView.addObject("resultMessage", "로그인에 실패하였습니다.");
        }

        return jsonView;
    }

    /**
     * 회원탈퇴 한다.
     * 
     * @param interfaceVO
     *            - 탈퇴 할 정보가 담긴 InterfaceiOSAPIVO
     * @param status
     * @return "forward:/itf/withdrawal.do"
     * @exception Exception
     */
    @ApiOperation(value="Interface 회원탈퇴", notes="[iOS] 회원탈퇴 한다.", response=InterfaceiOSAPIVO.class)
    @ApiImplicitParams({
    	@ApiImplicitParam(name = "userId", value = "아이디", required = true, dataType = "string", paramType = "query"),
    	@ApiImplicitParam(name = "userPw", value = "비밀번호", required = true, dataType = "string", paramType = "query"),
    })
    @RequestMapping("/itf/withdrawaliOS.do")
    public ModelAndView withdrawal(
            InterfaceiOSAPIVO interfaceVO, BindingResult bindingResult,
            Model model, SessionStatus status) throws Exception {

        ModelAndView jsonView = new ModelAndView("jsonView");

        int cnt = egovInterfaceAPIService.deleteInterfaceInfo(interfaceVO);

        if (cnt > 0) {
            jsonView.addObject("resultState", "OK");
            jsonView.addObject("resultMessage", "탈퇴에 성공하였습니다.");
        } else {
            jsonView.addObject("resultState", "FAIL");
            jsonView.addObject("resultMessage", "탈퇴에 실패하였습니다.");
        }

        return jsonView;
    }
}
