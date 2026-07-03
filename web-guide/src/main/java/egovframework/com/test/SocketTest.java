package egovframework.com.test;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SocketTest {
	
	//2017-03-08 조성원 시큐어코딩(ES)-제거되지 않고 남은 디버그 코드[CWE-489]
	private static final Logger LOGGER = LoggerFactory.getLogger(SocketTest.class);

	public static void main(String[] args) {
		try{
			InetAddress iAddress = InetAddress.getLocalHost();
			//System.out.println("Current IP Address:" + iAddress.getHostAddress());
            
			
			ServerSocket serverSocket = new ServerSocket(0);
            System.out.println("I'm waiting here: "+ iAddress.getHostAddress() + ":"+serverSocket.getLocalPort());            
            
            String itt = serverSocket.getInetAddress().getHostAddress();
            //System.out.println(">>t:" + itt);
            
            Socket socket = serverSocket.accept();
            //System.out.println("from " + 
            //    socket.getInetAddress() + ":" + socket.getPort());
            //2017-03-08 조성원 시큐어코딩(ES)-제거되지 않고 남은 디버그 코드[CWE-489]
    		LOGGER.debug("from " + 
                    socket.getInetAddress() + ":" + socket.getPort());
            
            OutputStream outputStream = socket.getOutputStream();
            PrintStream printStream = new PrintStream(outputStream);
            printStream.print("Server Message : Hello! This is Send data ~~ ");
            printStream.close();
            
            socket.close();
        }catch(IOException e){
            System.out.println(e.toString());
        }
	}
}
