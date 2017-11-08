
import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;
import javax.net.ssl.*;
import com.sun.net.ssl.*;
import com.sun.net.ssl.internal.ssl.Provider;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.security.cert.X509Certificate;


public class Server implements Runnable {

	private String settings; //charAt(0) = encr, (1) = integrity, (2) = authentication
	BufferedReader console, dataIn;
	PrintWriter dataOut;
	Thread sending, receiving;
	ServerSocket serversocket = null;
	boolean authentFlag, 
		integFlag,
		encrypFlag,
		validConnection;

	String in="",out="", clientSett = "";

		

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

	private boolean validateSettings(String settings, BufferedReader dataIn){
		try{
			System.out.println("Server chat settings: " +settings );
			clientSett = dataIn.readLine();
			System.out.println("Client settings selected: "+ clientSett);
			if (!clientSett.equals(settings)){
				System.out.println("Settings - Error, different settings selected from Client, restarting server");
				dataOut.println("false");
				validConnection = false;
				return false;
			}
			dataOut.println("true"); //Settings match

			encrypFlag = (settings.charAt(0) == '1') ? true : false;
			integFlag = (settings.charAt(1) == '1') ? true : false;
			authentFlag = (settings.charAt(2) == '1') ? true : false;

			
		}catch (Exception e){
			System.out.println("Settings - Connection Error");
		}
		return true;

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


	private static boolean validUser(PrintWriter dataOut, BufferedReader dataIn){
		boolean found = false;
		String [] utoken = null;

		System.out.println("Waiting for client credentials...");
		try{
			String user = dataIn.readLine();
			String pass = dataIn.readLine();
			System.out.println("Authentication - user: "+ user + " passhash:"+ pass);
			File file = new File ("./Servercred/credentials.txt");
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

	public Server() {
		Scanner scanner = new Scanner(System.in);

		while (true){
			clientSett = "";
			authentFlag = false; integFlag = false; encrypFlag = false;
			System.out.println("\n===========SERVER INITIALIZED===========");

			try{
				validConnection = true;
				serversocket = new ServerSocket(5000);
				System.out.println("Waiting for client to connect...");
				Socket socket = serversocket.accept();
				System.out.println("Client connected with Ip: " +socket.getInetAddress().getHostAddress());

				console = new BufferedReader(new InputStreamReader(System.in));
				dataOut = new PrintWriter(socket.getOutputStream(), true);
				dataIn = new BufferedReader(new InputStreamReader(socket.getInputStream()));

				if (validConnection){
					System.out.println("\n===========SETTINGS VALIDATION===========");
					settings ="111";  
					//settings = chatSettings(scanner);
					validateSettings(settings, dataIn); //!!!!!!!!	
				}

				//Authentication process
				if (validConnection && authentFlag){
					System.out.println("Settings - Chat settings verified");
					System.out.println("\n===========AUTHENTICATION===========");
					
					//Client authentication with Server
					boolean validCredential = validUser(dataOut, dataIn); 
					System.out.println("AUTHENTICATION RES: " + validCredential);
					if (!validCredential){
						validConnection = false;
					    System.out.println("Authentication - Wrong user or password, terminating connection.");
					}

					//Server authentication with client
					if (validCredential){
						validCredential = sendPass(scanner, dataOut, dataIn); 
						if (!validCredential){
							validConnection = false;
						    System.out.println("Authentication - Wrong user or password, terminating connection.");
						}else{
							System.out.println("Authentication process completed");
							
						}
					}

				}





				//Initiate conversation
				if (validConnection ){
					System.out.println("\n===========CHAT INITIATED===========");
					sending = new Thread(this);
					receiving = new Thread(this);
					sending.start();
					receiving.start();
					sending.join();
					receiving.join();
					System.out.println("===========CHAT ENDED===========");
				}

				System.out.println("Restarting server...");
				serversocket.close();
				socket.close();

			} catch (Exception e) {
			    System.err.println("Unable to initiate connection.");
			    e.printStackTrace();
			    System.exit(1);
	

        }


		}



	}

	public void run() {

		try {
			if (Thread.currentThread() == sending) {

				//Server thread (sending)
				while(true) {
					//Checks if client has closed chat
					sending.sleep(500);
					if (!receiving.isAlive()){
					 	break;
					}
					//Checks if server has typed something
					if (console.ready()){
						in = console.readLine();
						if (in.equals("END")){
							dataOut.println("END");
							break;
						}
						dataOut.println(in);
					}
				} 

			//Client thread (receiving)
			} else {
				while(true) {
					out = dataIn.readLine();
					if (out.equals("END")){
						System.out.println("Connection has been terminated");			
						break;
					}
					System.out.println("Client says: " + out);
				} 
			}

		}catch (Exception e) {
			e.printStackTrace();
			System.exit(1);

		}
	}

	public static void main(String[] args) {
		new Server();
	}
}