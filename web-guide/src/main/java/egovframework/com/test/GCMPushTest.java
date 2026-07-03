package egovframework.com.test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.android.gcm.server.Message;
import com.google.android.gcm.server.MulticastResult;
import com.google.android.gcm.server.Result;
import com.google.android.gcm.server.Sender;

/**
 * @Class Name : GCMPushTest.java
 * @Description : GCMPushTest
 * @Modification GCMPushTest
 * @
 * @  수정일        수정자        수정내용
 * @ -------     --------    ---------------------------
 * @ 2017.02.15   최두영        시큐어코딩(ES)-오류 메시지를 통한 정보 노출[CWE-209]
 * @ 2017.03.08   조성원        시큐어코딩(ES)-제거되지 않고 남은 디버그 코드[CWE-489]
 */

public class GCMPushTest {

	//2017-02-15 최두영 시큐어코딩(ES)-오류 메시지를 통한 정보 노출[CWE-209] 34-34 관
	private static final Logger LOGGER = LoggerFactory.getLogger(GCMPushTest.class);
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Sender sender = new Sender("AIzaSyBViR58Xs0GV08YqGheREd0l1evL2wJFeE"); // 서버 API Key 입력
		String regId = "APA91bGKMTQJggaaZpZCXKJMN-zwXXEYn0MyyxcDpMhWwGhPb3aK7S3iUzrLZmPYxo_m_7WXpMQMkJVT3T7MB9X0fteNUC2JX9z31WdwPmqBbXWZ7esoYhCQfllVlF5_x-cnJ0KfwBHB"; // 단말기 RegID 입력
		 
		Message message = new Message.Builder().addData("msg", "push notify!!! syh").build();
		List<String> list = new ArrayList<String>();
		list.add(regId);
		MulticastResult multiResult;
		
		try {
			multiResult = sender.send(message, list, 5);
			if (multiResult != null) {
				List<Result> resultList = multiResult.getResults();
				for (Result result : resultList) {
					//2017-03-08 조성원 시큐어코딩(ES)-제거되지 않고 남은 디버그 코드[CWE-489]
					//System.out.println(result.getMessageId());
					LOGGER.debug(">>> result : "+ result.getMessageId());
				}
			}
		} catch (IOException e) {
			//2017-02-15 최두영 시큐어코딩(ES)-오류 메시지를 통한 정보 노출[CWE-209] 34-34
			// TODO Auto-generated catch block
			//e.printStackTrace();
			LOGGER.error( "["+e.getClass()+"] try multiResult : " + e.getMessage());
		}
	}
	
}
