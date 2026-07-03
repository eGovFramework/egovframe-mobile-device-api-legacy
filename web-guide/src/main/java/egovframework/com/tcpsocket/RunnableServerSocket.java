package egovframework.com.tcpsocket;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.util.Observable;

/**
 * @Class Name : RunnableServerSocket.java
 * @Description : RunnableServerSocket
 * @Modification : 
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------   --------    ---------------------------
 * @ 2019.08.16   신용호              최초 작성
 */

public class RunnableServerSocket extends Observable implements Runnable {

	private final Socket socket; //initialize in const'r
	
	public RunnableServerSocket(Socket socket) {
		this.socket = socket;
	}

	@Override
	public void run() {

		try {

			/*BufferedWriter bufWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
			bufWriter.write("welcome Socket Server~!");
			bufWriter.newLine();
			bufWriter.flush();*/

			// client가 보낸 데이터 출력
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
	        String message;

	        while ((message = in.readLine())!=null) {
	        	Thread.sleep(200);
	        	System.out.println("Runnable > Server recieve message : " + message);
	        	
				setChanged();
				notifyObservers(message);
	        	
	        	//if ( !socket.getKeepAlive() ) {
	        	//	socket.close();
	        	//	break;
	        	//}
	        } //... close socket, etc.
	        System.out.println("Runnable > Server : Socket Closed~!");
	        System.out.println("Runnable > Server : Socket Remote Address = "+socket.getRemoteSocketAddress());
	        System.out.println("Runnable > Server : Socket Remote LocalAddress = "+socket.getLocalAddress());
	        System.out.println("Runnable > Server : Socket Remote LocalSocketAddress = "+socket.getLocalSocketAddress());
	        System.out.println("Runnable > Server : Socket Remote InetAddress = "+socket.getInetAddress());

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println(">>> IOException");
			closeSocket();
			
		} catch (InterruptedException e) {
			e.printStackTrace();
			System.out.println(">>> InterruptedException");
			closeSocket();
		}

    }
	
	public Socket getSocket() {
		return this.socket;
	}
	
	private void closeSocket() {
		try {
			this.socket.close();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}
	
}
