import java.io.*;
import java.net.*;
import java.util.*;
import javax.net.ssl.*;
import com.sun.net.ssl.*;
import java.math.BigInteger;
import java.security.*;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import com.sun.net.ssl.internal.ssl.Provider;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


public class Client implements Runnable {

	private String settings; //chatAt(0) = encr, (1) = integrity, (2) = authentication
	BufferedReader console, dataIn;
	PrintWriter dataOut;
	Thread receiving, sending;
	boolean authentFlag, 
		integFlag,
		encrypFlag,
		validConnection;
	
	String in = "", out = "";

	private static String chatSettings(Scanner in){
		String holder, settings = "";
		System.out.println("Please choose the chat settings...");
		
		System.out.println("(Encryption) - Would you like your messages to be encrypted? (y or n)");
		holder = in.next();
		while (holder.length() != 1 ){
			System.out.println("Wrong input, use 'y' or 'n'");
			holder = in.next();
		}
		settings  += ( holder.equals("y")|| holder.equals("Y")) ? 1 : 0;

		System.out.println("(Integrity) - Would you like to check integrity on messages? (y or n)");
		holder = in.next();
		while (holder.length() != 1 ){
			System.out.println("Wrong input, use 'y' or 'n'");
			holder = in.next();
		}
		settings  += ( holder.equals("y")|| holder.equals("Y")) ? 1 : 0;

		System.out.println("(Authentication) - Would you like to authenticate messages? (y or n)");
		holder = in.next();
		while (holder.length() != 1 ){
			System.out.println("Wrong input, use 'y' or 'n'");
			holder = in.next();
		}
		settings  += ( holder.equals("y")|| holder.equals("Y")) ? 1 : 0;

		return settings;
	}

	//Converts a byte array into a string in hex representation.
	public static String bytesToHex (byte[] bytes){
		StringBuilder builder = new StringBuilder();

		for(byte b : bytes) {
			builder.append(String.format("%02x", b));
		}
		return builder.toString(); 
	}

	private static byte[] hash (String stringy) throws Exception{
		byte[] digest = new byte[0];
		byte[] bytesOfMessage = stringy.getBytes("UTF-8");
		// System.out.println("bytes username: "+ bytesToHex(bytesOfMessage));
		MessageDigest md = MessageDigest.getInstance("MD5");
		digest = md.digest(bytesOfMessage);
		 // System.out.println("bytes digest: "+digest);
		 // System.out.println("hex digest: "+ bytesToHex(digest));

		return digest;
	}

	private static boolean sendPass(Scanner scanner, PrintWriter dataOut, BufferedReader dataIn){
		System.out.println("LOGIN: Please enter your username:");
		String userName = scanner.nextLine();
        System.out.println("userName: " + userName);
		dataOut.println(userName);
		System.out.println("LOGIN: Please enter your password:");
		String pass = scanner.nextLine();
		try{
			dataOut.println(bytesToHex(hash(pass)));
			String access = dataIn.readLine();
			if (access.equals("false")){
				return false;
			}
            return true;
		}catch(Exception e){
			e.printStackTrace();
			System.out.println("Hash - Error while hashing the string");
		}
        return false;
	}

	private static boolean validUser(PrintWriter dataOut, BufferedReader dataIn){
		boolean found = false;
		String [] utoken = null;

		System.out.println("Client credentials verification completed");
		System.out.println("Waiting for client credentials...");

		try{
			String user = dataIn.readLine();
			String pass = dataIn.readLine();

			System.out.println("Authentication - user: "+ user + " passhash:"+ pass);


			File file = new File ("./Clientcred/credentials.txt");
			Scanner fileScanner = new Scanner (file);
			while (fileScanner.hasNextLine()){
				utoken = fileScanner.nextLine().split(" ");
				if (utoken[0].equals(user)){
					found = true;
				}
				if (found){
					String preHash = utoken[1] + pass;
					String postHash = bytesToHex(hash(preHash));
					if (postHash.equals(utoken[2])){
						dataOut.println("true");
						return true;
					}
				}
			}

		}catch (Exception e){
			e.printStackTrace();
			System.out.println("Autentication ERROR - Problem hashing password");
		}
		dataOut.println("false");
		return false;
	}

	public Client() {
		Scanner scanner = new Scanner(System.in);

		while (true){
			Socket socket;

			try {
				System.out.println("\n===========CLIENT INITIALIZED===========");
				validConnection = true;
				System.out.println("Connecting to server...");

				socket = new Socket("localhost", 5000);

				console = new BufferedReader(new InputStreamReader(System.in));
				dataIn = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				dataOut = new PrintWriter(socket.getOutputStream(), true);


				//Chat settings validation
				if (validConnection){
					System.out.println("\n===========SETTINGS VALIDATION===========");
					System.out.println("Authentication - Login validation successful.");
					scanner = new Scanner(System.in);
					//settings = chatSettings(scanner); //!!!!!
					settings = "111";
					System.out.println("Client chat settings: " +settings );
					dataOut.println(settings);
					System.out.println("Waiting for sever to select chat settings...");
					String sett = dataIn.readLine();

					if (sett.equals("false")){
						System.out.println("Settings - Error, different settings selected from Client, restarting program...");
						validConnection = false;
					}
					encrypFlag = (settings.charAt(0) == '1') ? true : false;
					integFlag = (settings.charAt(1) == '1') ? true : false;
					authentFlag = (settings.charAt(2) == '1') ? true : false;
				}

				//Authentication process
				if (validConnection && authentFlag){
					System.out.println("Settings - Chat settings verified");
					System.out.println("\n===========AUTHENTICATION===========");
					
					//Client authentication with Server
					boolean validCredential = sendPass(scanner, dataOut, dataIn); 
					if (!validCredential){
						validConnection = false;
					    System.out.println("Authentication - Wrong user or password, terminating connection.");
					}
					//Server authentication with Client
					if (validCredential){
						validCredential = validUser(dataOut, dataIn); 
						if (!validCredential){
							validConnection = false;
						    System.out.println("Authentication - Wrong user or password, terminating connection.");
						}else{
							System.out.println("Authentication process completed");
							
						}
					}

				}




				//Initiate conversation
				if (validConnection){
					System.out.println("\n===========CHAT INITIATED===========");
				

					receiving = new Thread(this);
					sending = new Thread(this);
					receiving.start();
					sending.start();
					receiving.join();
					sending.join();

					System.out.println("===========CHAT ENDED===========");
					String request = "";
					System.out.println("Type 'open session' to start connection with server");
					request = scanner.nextLine();

					while (!request.equals("open session")){
						System.out.println("Command not valid, type 'open session' to start connection with server");
						request = scanner.nextLine();
					}
					socket.close();
					Thread.sleep(1000);
					System.out.println("Client - END of Main ++++++++++++");  
				}




			} catch (IOException e) {
				e.printStackTrace();
				System.err.println("Connection to server lost.");
			} catch (InterruptedException e2){
				e2.printStackTrace();
				System.err.println("Thread error.");

			}


		

		}

		
}

	public void run() {
		try {

			//Client thread (sending)              
			if (Thread.currentThread() == sending) {
				while (true){
					sending.sleep(500);
					if (!receiving.isAlive()){
						// System.out.println("sending EXITING thread++++++");
						break;
					}
					if (console.ready()){
						in = console.readLine();
						if (in.equals("END")){
							System.out.println("Chat has been closed by client.");
							dataOut.println("END");
							// System.out.println("t2 EXITING thread ++++++++++++++");
							break;
						}
						dataOut.println(in);
					}
				}

			//Server thread (receiving)
			}else {
				while(true) {
					//Checks if server has closed chat
					receiving.sleep(500);
					if (!sending.isAlive()){
						// System.out.println("receiving EXITING thread++++++");
						break;
					}
					if (dataIn.ready()){
						out = dataIn.readLine();
						if (out.equals("END")){
							System.out.println("Server has closed the connection.");
							dataOut.println("END");
							// System.out.println("receiving EXITING thread++++++++++++++");
							break;
						}
						System.out.println("Server says: " + out);
					}
				}
			}
		}catch (Exception e) {
		}

	}

	 public static void main(String[] args) {
		new Client();
	}
}