package egovframework.com.push;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import javapns.communication.ConnectionToAppleServer;
import javapns.communication.exceptions.CommunicationException;
import javapns.communication.exceptions.KeystoreException;
import javapns.devices.Device;
import javapns.devices.implementations.basic.BasicDevice;
import javapns.notification.AppleNotificationServerBasicImpl;
import javapns.notification.PushNotificationManager;
import javapns.notification.PushNotificationPayload;
import javapns.notification.PushedNotification;

/**
 * @Class Name : ANPSPush.java
 * @Description : APNSPush
 * @Modification Push
 * @
 * @  수정일        수정자        수정내용
 * @ -------     --------    ---------------------------
 * @ 2017.02.14   최두영        시큐어코딩(ES) - 오류 메시지를 통한 정보 노출[CWE-209]
 */

public class APNSPush {

	private static String   CERTIFICATE_PATH = "C:/eclipse-jee-mars-2-win32-x86_64/egov_push_test_cert.p12";
	private static String   CERTIFICATE_PWD  = "egov1234";      // 푸시 인증서 비밀번호
	private static String   APNS_DEV_HOST  = "gateway.sandbox.push.apple.com"; // 개발용 푸시 전송서버 
	private static String   APNS_HOST   = "gateway.push.apple.com";  // 운영 푸시 전송서버
	private static int      APNS_PORT   = 2195;      // 이건..개발용 운영용 나뉘는지 확인해보자
	private static int   BADGE    = 1;       // App 아이콘 우측상단에 표시할 숫자
	private static String  SOUND    = "default";      // 푸시 알림음
	
	//2017-02-14 최두영 시큐어코딩(ES) - 오류 메시지를 통한 정보 노출[CWE-209] 110-110관련 
	private static final Logger LOGGER = LoggerFactory.getLogger(APNSPush.class);
	
	public static void main(String[] args) {

		ArrayList<String> myTokens = new ArrayList<String>();
		myTokens.add("5074db1006a246d508b58c458dedddcfb3fb3063b04acde57418ec7d0d4e2737");
		HashMap<String, Object> map_pushInfo = new HashMap<String, Object>();
		map_pushInfo.put("sender_nick", "mycomghost");
		map_pushInfo.put("msg", "this is a push test!!!");
		
		int result = sendPush_IOS(myTokens, map_pushInfo);
		System.out.println(">>> result : " + result);
	}

	
	public static int sendPush_IOS(ArrayList<String> tokens, HashMap<String, Object> map_pushInfo){
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
		    jo_aps.put("badge",BADGE);
		    jo_aps.put("sound",SOUND);
		    jo_aps.put("content-available",1);
		    
		    jo_body.put("aps",jo_aps);
		    jo_body.put("sender_nick",sender_nick);
		    payLoad = payLoad.fromJSON(jo_body.toString());
		    
		    PushNotificationManager pushManager = new PushNotificationManager();
		             pushManager.initializeConnection(
		               new AppleNotificationServerBasicImpl(CERTIFICATE_PATH, CERTIFICATE_PWD,ConnectionToAppleServer.KEYSTORE_TYPE_PKCS12, APNS_DEV_HOST, APNS_PORT));
		             
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
		               result = 2; // 푸시 실패건 발생
		              }else{
		               result = 1; // 푸시 모두 성공
		              }
		         }catch(KeystoreException ke){
		          result = 9;
		          //2017-02-14 최두영 시큐어코딩(ES) - 오류 메시지를 통한 정보 노출[CWE-209]
		          LOGGER.error("[KeystoreException] try PushNotification : " + ke.getMessage());
		         }catch(CommunicationException ce){
		          result = 9;
		          //2017-02-14 최두영 시큐어코딩(ES) - 오류 메시지를 통한 정보 노출[CWE-209]
		          LOGGER.error("[CommunicationException] try PushNotification : " + ce.getMessage());
		         }catch (Exception e) {
		          result = 9;
		          //2017-02-14 최두영 시큐어코딩(ES) - 오류 메시지를 통한 정보 노출[CWE-209] 110-110
		          //e.printStackTrace();
		          LOGGER.error("["+e.getClass()+"] try PushNotification : " + e.getMessage());
		         }
		  return result;
		 }
	
}
