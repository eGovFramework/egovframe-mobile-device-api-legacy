package egovframework.com.tcpsocket;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Observable;
import java.util.Observer;

/**
 * @Class Name : ResponseHandler.java
 * @Description : ResponseHandler
 * @Modification : 
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------   --------    ---------------------------
 * @ 2019.08.16   신용호              최초 작성
 */

public class ResponseHandler implements Observer {

	private String resp;
	private List<Socket> list = new ArrayList<Socket>();

	public void update(Observable obj, Object arg) {
		if (arg instanceof String) {
			resp = (String) arg;
			System.out.println("ResponseHandler > bserver Received Response: " + resp);
			System.out.println("ResponseHandler > Socket Connection Count = " + list.size());
			
			for(Iterator<Socket> it = list.iterator() ; it.hasNext() ; )
			{
				Socket socket = it.next();
				System.out.println("ResponseHandler > start > ==========================");
				System.out.println("ResponseHandler > Socket info = " + socket);
				System.out.println("ResponseHandler > Socket info > socket.isClosed() = " + socket.isClosed());
				System.out.println("ResponseHandler > Socket info > socket.isConnected() = " + socket.isConnected());
				System.out.println("ResponseHandler > Socket info > socket.isInputShutdown() = " + socket.isInputShutdown());
				System.out.println("ResponseHandler > Socket info > socket.isOutputShutdown() = " + socket.isOutputShutdown());
				
				if( socket.isClosed() ) {
					System.out.println("ResponseHandler > isClosed() = "+socket.isClosed());
					System.out.println("ResponseHandler > List<Socket> is removed!");
					it.remove();
				} else {
					System.out.println("ResponseHandler > Socket Connection > echo ");
					BufferedWriter bufWriter;
					try {
						bufWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
						bufWriter.write(""+resp);
						bufWriter.newLine();
						bufWriter.flush();

					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				System.out.println("ResponseHandler > finish > ==========================");
			}
		}
	}
	
	public void addSocket(Socket socket) {
		synchronized (list) {
			this.list.add(socket);
			System.out.println("===>>> ResponseHandler > add > count = "+ list.size());
		}
	}
	
	public void removeSocket(Socket socket) {
		synchronized (list) {
			this.list.remove(socket);
			System.out.println("===>>> ResponseHandler > remove > count = "+ list.size());
		}
	}
	
}
