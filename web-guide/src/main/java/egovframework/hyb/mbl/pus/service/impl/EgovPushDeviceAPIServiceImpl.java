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
package egovframework.hyb.mbl.pus.service.impl;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import javax.annotation.Resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;

import egovframework.com.cmm.service.EgovProperties;
import egovframework.hyb.mbl.pus.service.EgovPushDeviceAPIService;
import egovframework.hyb.mbl.pus.service.PushDeviceAPIDefaultVO;
import egovframework.hyb.mbl.pus.service.PushDeviceAPIVO;
import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;
import javapns.communication.ConnectionToAppleServer;
import javapns.communication.exceptions.CommunicationException;
import javapns.communication.exceptions.KeystoreException;
import javapns.devices.Device;
import javapns.devices.implementations.basic.BasicDevice;
import javapns.notification.AppleNotificationServerBasicImpl;
import javapns.notification.PushNotificationManager;
import javapns.notification.PushNotificationPayload;
import javapns.notification.PushedNotification;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
/**  
 * @Class Name : EgovPushDeviceAPIServiceImpl.java
 * @Description : EgovPushDeviceAPIServiceImpl Class
 * @Modification Information  
 * @
 * @  수정일       수정자                   수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2016.06.20   신성학                   최초생성
 * @ 2017.02.15   최두영        시큐어코딩(ES)-오류 메시지를 통한 정보 노출[CWE-209]
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 06.20
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by Ministry of Interior All right reserved.
 */

@Service("EgovPushDeviceAPIService")
public class EgovPushDeviceAPIServiceImpl extends EgovAbstractServiceImpl implements EgovPushDeviceAPIService {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(EgovPushDeviceAPIServiceImpl.class);
	private static final ObjectMapper MAPPER = new ObjectMapper();

	private static String   APNS_CERTIFICATE_PATH	= "C:/eclipse-jee-mars-2-win32-x86_64/egov_push_test_cert.p12";
	private static String   APNS_CERTIFICATE_PWD	= "egov1234";      // 푸시 인증서 비밀번호
	private static String   APNS_DEV_HOST	= "gateway.sandbox.push.apple.com"; // 개발용 푸시 전송서버 
	private static String   APNS_HOST		= "gateway.push.apple.com";  // 운영 푸시 전송서버
	private static int      APNS_PORT		= 2195;      // 이건..개발용 운영용 나뉘는지 확인해보자
	private static int   	APNS_BADGE		= 1;       // App 아이콘 우측상단에 표시할 숫자
	private static String	APNS_SOUND		= "default";      // 푸시 알림음
	
	private static String	GCM_SERVER_API_KEY	= "AIzaSyD1kFG9Z3Kw-rvQgCl-0t4idpDetYE3UYM"; // GCM Server API Key
	
	
	/** PushAPIDAO */
    @Resource(name="PushDeviceAPIDAO")
    private PushDeviceAPIDAO pushDeviceAPIDAO;

	/**
	 * 알림 설정 정보를 등록한다.
	 * @param vo - 등록할 정보가 담긴 PushDeviceAPIVO
	 * @return 등록 결과
	 */

/*    public int insertVibrator(PushDeviceAPIVO vo) {
    	LOGGER.debug(vo.toString());
    	
    	return (Integer)PushDeviceAPIVO.insertVibrator(vo);    	
    }
    */
    /**
	 * 알림 설정 정보 목록을 조회한다.
	 * @param VO - 조회할 정보가 담긴 VibratorAPIVO
	 * @return 알림 설정 정보 목록
	 */
    public List<?> selectPushDeviceList(PushDeviceAPIDefaultVO searchVO) {
        return pushDeviceAPIDAO.selectPushDeviceList(searchVO);
    }
    
	/**
	 * Push Notification을 위해 Device 정보를 등록한다.
	 * @param vo - 등록할 정보가 담긴 PushAPIVO
	 * @return 등록 결과
	 */
    public int insertPushDevice(PushDeviceAPIVO vo) {
    	LOGGER.debug(vo.toString());
    	
    	return (Integer)pushDeviceAPIDAO.insertPushDevice(vo);
    }
    
	/**
	 * Push Notification을 서버에 요청한다.
	 * @param vo - 등록할 정보가 담긴 PushAPIVO
	 * @return 등록 결과
	 */
    public int insertPushInfo(PushDeviceAPIVO vo) {
    	LOGGER.debug(vo.toString());
    	
    	// Android GCM, iOS APNS 푸쉬 메시지를 발송한다.
    	if (vo.getOsType().contains("Android")) {
    		sendFCMAndroid(vo.getTokenId(), vo.getMessage());
    	} else {
    		sendAPNSPush(vo.getTokenId(), vo.getMessage());
    	}

    	return (Integer)pushDeviceAPIDAO.insertPushInfo(vo);    	
    }

    public int sendAPNSPush(String tokenId, String pushMessage) {

    	ArrayList<String> myTokens = new ArrayList<String>();
		myTokens.add(tokenId);
		HashMap<String, Object> map_pushInfo = new HashMap<String, Object>();
		map_pushInfo.put("sender_nick", "egovDeviceAPI");
		map_pushInfo.put("msg", pushMessage);
		
		int result = sendPushIOS(myTokens, map_pushInfo);

    	return result;
    }
    
	public int sendPushIOS(ArrayList<String> tokens, HashMap<String, Object> map_pushInfo){
		  // 아이폰 푸시전송 - 최대 한글전송길이 45글자 (보낸이 + 내용)
		 
		  int result = 0;
		 
		  // 1. 푸시 기본정보 초기화
		 
		  String sender_nick  = (String)map_pushInfo.get("sender_nick");
		  String msg   = (String)map_pushInfo.get("msg");
		  
		  // 2. 싱글캐스트 or 멀티캐스트 구분
		   boolean single_push = true; 
		   if(tokens.size()==1){
		    single_push = true;    
		   }else{
		    single_push = false;
		   }
		 
		   try{
		    // 3. 푸시 데이터 생성
		    PushNotificationPayload payLoad = new PushNotificationPayload();
		    ObjectNode jo_body = JsonNodeFactory.instance.objectNode();
		    ObjectNode jo_aps = JsonNodeFactory.instance.objectNode();
		    jo_aps.put("alert",msg);
		    jo_aps.put("badge",APNS_BADGE);
		    jo_aps.put("sound",APNS_SOUND);
		    jo_aps.put("content-available",1);
		    
		    jo_body.put("aps",jo_aps);
		    jo_body.put("sender_nick",sender_nick);
		    payLoad = payLoad.fromJSON(jo_body.toString());
		    
		    PushNotificationManager pushManager = new PushNotificationManager();
		             pushManager.initializeConnection(
		               new AppleNotificationServerBasicImpl(APNS_CERTIFICATE_PATH, APNS_CERTIFICATE_PWD,ConnectionToAppleServer.KEYSTORE_TYPE_PKCS12, APNS_DEV_HOST, APNS_PORT));
		             
		             List<PushedNotification> notifications = new ArrayList<PushedNotification>();
		             
		             if (single_push){
		              // 싱글캐스트 푸시 전송
		                Device device = new BasicDevice();
		                device.setToken(tokens.get(0));
		                PushedNotification notification = pushManager.sendNotification(device, payLoad);
		                notifications.add(notification);
		             }else{
		              // 멀티캐스트 푸시 전송
		                 List<Device> device = new ArrayList<Device>();
		                 for (String token : tokens){
		                     device.add(new BasicDevice(token));
		                 }
		                 notifications = pushManager.sendNotifications(payLoad, device);
		             }
		              List<PushedNotification> failedNotifications = PushedNotification.findFailedNotifications(notifications);
		              List<PushedNotification> successfulNotifications = PushedNotification.findSuccessfulNotifications(notifications);
		              int failed = failedNotifications.size();
		              int successful = successfulNotifications.size();
		              if(failed > 0){
		               result = 1; // 푸시 실패건 발생
		              }else{
		               result = 0; // 푸시 모두 성공
		              }
		         }catch(KeystoreException ke){
		          result = 2;
		          LOGGER.error("[KeystoreException] Try/Catch...KeystoreException : " + ke.getMessage());
		         }catch(CommunicationException ce){
		          result = 3;
		          LOGGER.error("[CommunicationException] Try/Catch...CommunicationException : " + ce.getMessage());
		         }catch (Exception e) {
		          result = 4;
		          //2017-02-15 최두영 시큐어코딩(ES)-오류 메시지를 통한 정보 노출[CWE-209] 251-251
		          //e.printStackTrace();
		          LOGGER.error("["+e.getClass()+"] PushNotification : " + e.getMessage());
		         }
		  return result;
		 }
	
	/**
	 * Push Notification 기기 상세 조회를 한다.
	 * @param vo - 등록할 정보가 담긴 PushDeviceAPIVO
	 * @return 조회 결과
	 */
    public PushDeviceAPIVO selectPushDevice(PushDeviceAPIVO vo) {
        return pushDeviceAPIDAO.selectPushDevice(vo);
    }
    
	/**
	 * Push Notification 송신 메세지 조회를 한다.
	 * @param vo - 등록할 정보가 담긴 PushDeviceAPIVO
	 * @return 조회 결과
	 */
    public List<?> selectPushMessageList(PushDeviceAPIVO VO) {
        return pushDeviceAPIDAO.selectPushMessageList(VO);
    }

    /**
     * Push Notification 등록된 기기가 있는지 조회를 한다.
     * @param VO
     * @return
     */
    public int selectPushDeviceCount(PushDeviceAPIVO vo) {
    	return pushDeviceAPIDAO.selectPushDeviceCount(vo);
    }

    /**
     * 안드로이드 푸시 전송
     * @param pushRegId
     * @param pushMessage
     * @return
     */
    public int sendFCMAndroid(String pushRegId, String pushMessage) {

    	int result = 0;

    	try {

	    	// AccessKey  경로
	    	String PATH = EgovProperties.getPathProperty("Globals.fcmSdk");
	    	String MESSAGING_SCOPE = EgovProperties.getProperty("Globals.fcmMessagingScope");
	    	String[] SCOPES = { MESSAGING_SCOPE };
	    	GoogleCredential googleCredential = GoogleCredential.fromStream(new FileInputStream(PATH)).createScoped(Arrays.asList(SCOPES));
	    	googleCredential.refreshToken();

	    	// HTTP 헤더에 AccessKey 등록
	    	HttpHeaders headers = new HttpHeaders();
	    	headers.add("Authorization", "Bearer " + googleCredential.getAccessToken());
	    	headers.add("content-type", MediaType.APPLICATION_JSON_VALUE);

	    	ObjectNode notification = JsonNodeFactory.instance.objectNode();
	    	notification.put("title", "FCM Test Title"); // Push 제목
	    	notification.put("body", pushMessage); // Push 내용

	    	ObjectNode message = JsonNodeFactory.instance.objectNode();
	    	message.put("token", pushRegId); // 디바이스 토큰
	    	message.put("notification", notification);

	    	ObjectNode jsonParams = JsonNodeFactory.instance.objectNode();
	    	jsonParams.put("message", message);

	    	HttpEntity<String> httpEntity = new HttpEntity<String>(MAPPER.writeValueAsString(jsonParams), headers);
	    	RestTemplate rt = new RestTemplate();

	    	// 요청할 주소(.../projects/{등록한 프로젝트 ID 기입}/messages...)
	    	ResponseEntity<String> res = rt.exchange(
		    	EgovProperties.getProperty("Globals.fcmRequestPath")
		    	, HttpMethod.POST
		    	, httpEntity
		    	, String.class
	    	);

	    	if (res.getStatusCode() != HttpStatus.OK) {
		    	result = 1;
	    	} else {
		    	result = 0;
	    	}

    	} catch (FileNotFoundException fnfe) {
    		LOGGER.error("["+fnfe.getClass()+"] FileNotFoundException : " + fnfe.getMessage());
    	} catch (IOException ioe) {
    		LOGGER.error("["+ioe.getClass()+"] IOException : " + ioe.getMessage());
    	}

    	return result;
    }

}
