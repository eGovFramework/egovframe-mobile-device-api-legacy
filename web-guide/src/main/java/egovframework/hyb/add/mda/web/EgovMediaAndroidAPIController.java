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
package egovframework.hyb.add.mda.web;

import java.util.List;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import egovframework.hyb.add.mda.service.EgovMediaAndroidAPIService;
import egovframework.hyb.add.mda.service.MediaAndroidAPIFileVO;
import egovframework.hyb.add.mda.service.MediaAndroidAPIVO;
import egovframework.hyb.add.mda.service.MediaAndroidAPIXmlVO;
import egovframework.com.cmm.security.DeviceAPIAuthSupport;
import egovframework.hyb.add.mda.service.impl.EgovMediaAndroidFileMngUtil;
import egovframework.rte.fdl.property.EgovPropertyService;
/**  
 * @Class Name : EgovMediaAndroidAPIController.java
 * @Description : EgovMediaAndroidAPIController Class
 * @Modification Information  
 * @
 * @ 수정일         수정자              수정내용
 * @ ----------   ---------------   -------------------------------
 *   2012.07.30   이율경              최초생성
 *   2020.09.07   신용호              Swagger 적용
 * 
 * @author 디바이스 API 실행환경 팀
 * @since 2012. 7. 30.
 * @version 1.0
 * @see
 * 
 */
@Controller
public class EgovMediaAndroidAPIController {

	/** EgovMediaAndroidAPIService */
	@Resource(name = "EgovMediaAndroidAPIService")
	private EgovMediaAndroidAPIService egovMediaAndroidAPIService;

	/** propertiesService */
	@Resource(name = "propertiesService")
	protected EgovPropertyService propertiesService;

	/** EgovFileMngUtil */
	@Resource(name = "EgovMediaAndroidFileMngUtil")
	private EgovMediaAndroidFileMngUtil egovMediaFileMngUtil;

	/**
	 * 녹음 파일을 등록한다. (업로드)
	 * @param file - 녹음 파일 정보가 담긴 MultipartFile
	 * @param fileVO - 등록 정보가 담긴 CameraAndroidAPIVO
	 * @return boolean
	 * @exception Exception
	 */
    @RequestMapping("/mda/mediaRecordUpload.do")
	public @ResponseBody
	boolean fileUpload(@RequestParam("file") MultipartFile file, MediaAndroidAPIVO vo, HttpServletRequest request) throws Exception {

		if (!file.isEmpty()) {

			MediaAndroidAPIFileVO fileVO = egovMediaFileMngUtil.writeUploadedFile(file);

			egovMediaAndroidAPIService.insertMediaInfo(vo, fileVO.getFileSn());

			return true;
		} else {

			return false;
		}
	}

	/**
	 * 미디어 정보를 조회한다.
	 * @param VO - 조회할 정보가 담긴 MediaAndroidAPIVO
	 * @return 조회 목록
	 * @exception Exception
	 */
    @RequestMapping("/mda/mediaInfoDetail.do")
	public @ResponseBody
	MediaAndroidAPIXmlVO selectMediaInfoDetail(MediaAndroidAPIVO vo) throws Exception {

		MediaAndroidAPIFileVO mediaInfo = egovMediaAndroidAPIService.selectMediaInfoDetail(vo);

		MediaAndroidAPIXmlVO mediaAndroidAPIXmlVO = new MediaAndroidAPIXmlVO();
		mediaAndroidAPIXmlVO.setMediaAndroidAPIFileVO(mediaInfo);

		return mediaAndroidAPIXmlVO;
	}

	/**
	 * 미디어 목록을 조회한다.
	 * @param VO - 조회할 정보가 담긴 MediaAndroidAPIVO
	 * @return 조회 목록
	 * @exception Exception
	 */
        	@SuppressWarnings("unchecked")
	@RequestMapping("/mda/mediaInfoList.do")
	public @ResponseBody
	MediaAndroidAPIXmlVO selectMediaInfoList(MediaAndroidAPIVO vo) throws Exception {

		List<MediaAndroidAPIVO> mediaList = (List<MediaAndroidAPIVO>) egovMediaAndroidAPIService.selectMediaInfoList(vo);

		MediaAndroidAPIXmlVO mediaAndroidAPIXmlVO = new MediaAndroidAPIXmlVO();
		mediaAndroidAPIXmlVO.setMediaAndroidAPIVOList(mediaList);

		return mediaAndroidAPIXmlVO;
	}

	/**
	 * 미디어 파일을 조회한다.
	 * @param fileVO - 조회할 정보가 담긴 CameraAndroidAPIFileVO
	 * @param model
	 * @param response
	 * @return jsonView
	 * @exception Exception
	 */
    @RequestMapping("/mda/getMedia.do")
	public void getImageInf(@RequestParam("sn") String sn,
			@RequestParam(value = "uuid", required = false) String uuid,
			HttpServletRequest request, HttpServletResponse response) throws Exception {

		if (sn != null && !"".equals(sn)) {
			MediaAndroidAPIFileVO vo = new MediaAndroidAPIFileVO();
			vo.setSn(Integer.parseInt(sn));
			vo.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, uuid));
			egovMediaAndroidAPIService.selectMediaFileInf(response, vo);
		}
	}
}
