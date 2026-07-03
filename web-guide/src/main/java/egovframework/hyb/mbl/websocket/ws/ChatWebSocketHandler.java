package egovframework.hyb.mbl.websocket.ws;

import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

/**
* @
* @ 수정일                          수정자                       수정내용
* @ ----------   ---------   -------------------------------
*   2024.05.02.   우시재 NSR    보안조치 ( XSS 방지 메소드 구현 및 소켓 메시지에 적용 )
*/

public class ChatWebSocketHandler extends TextWebSocketHandler {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(ChatWebSocketHandler.class);

	private Map<String, WebSocketSession> users = new ConcurrentHashMap<>();

	// 2024.05.02  NSR 보안조치 ( XSS 방지 메소드 구현 및 소켓 메시지에 적용 )
	public static class EgovWebUtil{
		public static String clearXSSMinimum(String value) {
			if(value == null || value.trim().equals("")) {
				return "";
			}
			String returnValue = value;
			returnValue = returnValue.replaceAll("&", "&amp;");
			returnValue = returnValue.replaceAll("<", "&lt;");
			returnValue = returnValue.replaceAll(">", "&gt;");
			returnValue = returnValue.replaceAll("\"", "&#34;");
			returnValue = returnValue.replaceAll("\'", "&#39;");
			returnValue = returnValue.replaceAll("\\.", "&#46;");
			returnValue = returnValue.replaceAll("%2E", "&#46;");
			returnValue = returnValue.replaceAll("%2F", "&#47;");
			return returnValue;
		}
		public static String getTextMessageContent(TextMessage message) {
			return message.getPayload();
		}
	}
	
	@Override
	public void afterConnectionEstablished(
			WebSocketSession session) throws Exception {
		log(session.getId() + " 연결 됨");
		users.put(session.getId(), session);
	}

	@Override
	public void afterConnectionClosed(
			WebSocketSession session, CloseStatus status) throws Exception {
		log(session.getId() + " 연결 종료됨");
		users.remove(session.getId());
	}

	@Override
	protected void handleTextMessage(
			WebSocketSession session, TextMessage message) throws Exception {
		log(session.getId() + "로부터 메시지 수신: " + message.getPayload());
		
		// 2024.05.02  NSR 보안조치 ( XSS 방지 메소드 구현 및 소켓 메시지에 적용 )
		String filteredMessage = EgovWebUtil.clearXSSMinimum(EgovWebUtil.getTextMessageContent(message));

		for (WebSocketSession s : users.values()) {
			// 2024.05.02  NSR 보안조치 ( XSS 방지 메소드 구현 및 소켓 메시지에 적용 )
			s.sendMessage(new TextMessage(filteredMessage));
			log(s.getId() + "에 메시지 발송: " + filteredMessage);
		}
	}

	@Override
	public void handleTransportError(
			WebSocketSession session, Throwable exception) throws Exception {
		log(session.getId() + " 익셉션 발생: " + exception.getMessage());
	}

	private void log(String logmsg) {
		LOGGER.info(new Date() + " : " + logmsg);
	}

}
