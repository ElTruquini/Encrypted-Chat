//
// ***************************************************************************************
// Developed by: Ben Wolfe (V00205547) and Daniel Olaya (V00855054)
// Course: SENG360 - Security Engineering
// Date: November, 2017
// Assignment 3 - Chat program that allows to users to communicate using different 
// security parameters such as encryption, integrity (digital signatures) and mutual authentication.
// ***************************************************************************************
//
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

// Implements the Client program, always connecting to server in port 5000.
public class Client implements Runnable {

	protected String settings; //chatAt(0) = encr, (1) = integrity, (2) = authentication
	BufferedReader console, dataIn;
	PrintWriter dataOut;
	DataInputStream dIn;
	DataOutputStream dOut;
	Thread receiving, sending;
	boolean authentFlag, 
		integFlag,
		encrypFlag,
		validConnection;
	
	String in = "", out = "";
	protected ClientSignature clientSignatureManager;
	protected AsymmetricCryptography ac;
	private byte[] clientPrivateKey, serverPublicKey;

	// Retreives user settings and appends result to string 'settings' which is later
	// used to compare with Server settings.
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

	// Method used to hash a string (password) which can be sent over an insecure connection.
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

	// Method takes login credentials from user and hashes the password to send over communication channel
	private static boolean sendPass(Scanner scanner, PrintWriter dataOut, BufferedReader dataIn){
		scanner = new Scanner(System.in);	
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

	// Method used to receive Serrver username and hashed password. If username exists on the credential.txt
	// database, then the password given by client will be hashed with the salt (utoken[1]). If the result
	// es equal to h(salt + h(pass)), then it is a valid password and 'true' will be returned.
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
				// Setting up connection
				System.out.println("\n===========CLIENT INITIALIZED===========");
				validConnection = true;
				System.out.println("Connecting to server...");
				socket = new Socket("localhost", 5000);

				console = new BufferedReader(new InputStreamReader(System.in));
				dataIn = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				dataOut = new PrintWriter(socket.getOutputStream(), true);

				// Settings parameters
				if (validConnection){
					System.out.println("\n===========SETTINGS VALIDATION===========");
					System.out.println("Connected to server...");
					scanner = new Scanner(System.in);

					// settings = "110"; //[0] Encryp, [1] Integ, [2] Auth
					settings = chatSettings(scanner);
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

				// Integrity parameters - Initialize client signatures.
				// This will only be done once per session (the files will be automatically overwrite each session)
				if (validConnection && (integFlag || encrypFlag)){
					System.out.println("\n===========GENERATING SIGNATURE KEYS===========");
					clientSignatureManager = new ClientSignature();
					clientSignatureManager.initializeClientSignature();
					System.out.println("Signature keys intialization completed...");

				}

				// Encryption parameters
				if (validConnection && encrypFlag){
					System.out.println("\n===========RETRIEVING ENCRYPTION KEYS===========");
					System.out.println("Retrieving public and private keys...");
					//Loading exiting client RSA public keys and server RSA private key
					ac = new AsymmetricCryptography();
					clientPrivateKey = ac.getPrivate("./Clientcred/clientRSAprivateKey").getEncoded();
					serverPublicKey = ac.getPublic("./Clientcred/serverRSApublicKey").getEncoded();
					//Used for sending byte array
					dOut = new DataOutputStream(socket.getOutputStream());
					dIn = new DataInputStream(socket.getInputStream());
				}

				//Initiate conversation (threads)
				if (validConnection){
					System.out.println("\n===========CHAT INITIATED===========");
					receiving = new Thread(this);
					sending = new Thread(this);
					receiving.start();
					sending.start();
					receiving.join();
					sending.join();
					System.out.println("===========END OF CHAT===========");
					System.out.println("Type 'open session' to start connection with server");
					scanner = new Scanner(System.in);
					String request = scanner.nextLine();
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
			} catch (Exception e3) {
			    e3.printStackTrace();
        	}
		}
	}

	public void run() {
		try {

			//Client sending thread              
			if (Thread.currentThread() == sending) {
				while (true){
					//Checks if server thread is still running
					sending.sleep(500);
					if (!receiving.isAlive()){
						break;
					}
					// Client send message
					if (console.ready()){
						in = console.readLine();
						if (in.equals("END")){
							System.out.println("Connection has been terminated");
							if (encrypFlag  && !integFlag){
								byte[] encryptedData = ac.encrypt(serverPublicKey, in.getBytes());
								dOut.writeInt(encryptedData.length);
								dOut.write(encryptedData);
								break;
							}else if (encrypFlag && integFlag) {
								String serverAfterSign = clientSignatureManager.signMessage(in); 
								// System.out.println("serverAfterSign: " + serverAfterSign);
								byte[] encryptedData = ac.encrypt(serverPublicKey, in.getBytes());
								dataOut.println(serverAfterSign);
							}
							else{
								dataOut.println("END");
								break;
							}
						}
						// (Integrity only) Client send
						if (integFlag && !encrypFlag){
							String clientAfterSign = clientSignatureManager.signMessage(in); 
							dataOut.println(clientAfterSign);
						}
						//(Encryption only) Client send
						else if (!integFlag && encrypFlag) {
							byte[] encryptedData = ac.encrypt(serverPublicKey, in.getBytes());
							// System.out.println("Sending: " + in + ", encrypted message: " + encryptedData);
							dOut.writeInt(encryptedData.length);
							dOut.write(encryptedData);
						}
						//(Encryption and Integrity) Client send
						else if (integFlag && encrypFlag) {
							String serverAfterSign = clientSignatureManager.signMessage(in); 
							// System.out.println("serverAfterSign: " + serverAfterSign);
							byte[] encryptedData = ac.encrypt(serverPublicKey, in.getBytes());
							dataOut.println(serverAfterSign);
						}
						// (No encryption, No integrity) - Client send plaintext
						else{
							dataOut.println(in);
						}
					}
				}

			//Client receiving thread 
			}else {
				while(true) {
					//Checks if server thread is running
					receiving.sleep(500);
					if (!sending.isAlive()){
						break;
					}
					//(Integrity only)
					if (!encrypFlag && integFlag){
						if (dataIn.ready()){
							out = dataIn.readLine();
							// Check if end of communication
							if (out.equals("END")){
								System.out.println("Server has closed the connection.");
								dataOut.println("END");
								break;
							}
							// (Integrity only) Client recieve
							if (integFlag){
								boolean validateServerSignature = clientSignatureManager.verifyMessage(out);
								if (validateServerSignature) {
									String message = out.split(":")[1]; 
									System.out.println("(Valid Sig.) - Server says: " + message);
								}else{
									String message = out.split(":")[1];
									System.out.println("(Invalid Sig.) - Server says: " + message);
								}
							} 							
						}
					}
					// (Encryption only) Client recieve - DataStreams used to send binary data
					else if (!integFlag && encrypFlag) {
						int length = dIn.readInt(); 
						byte[] message = new byte[length];
						
						if(length>0) {
						    dIn.readFully(message, 0, message.length); 
						}
						byte[] decryptedData = ac.decrypt(clientPrivateKey, message);
						String decrypt = new String(decryptedData);
						
						if (decrypt.equals("END")){
							System.out.println("Server has closed the connection.");
							byte[] encryptedData = ac.encrypt(serverPublicKey, decrypt.getBytes());
							dOut.writeInt(encryptedData.length);
							dOut.write(encryptedData);

							break;
						}
						System.out.println("(Decrypted message) - Server says: " + decrypt);
					}
					//(Encryption and Integrity) - Client receive
					else if (integFlag && encrypFlag){
						out = dataIn.readLine();
						boolean validateServerSignature = clientSignatureManager.verifyMessage(out);
						if (validateServerSignature) {
							String mess = out.split(":")[1]; 
							if (mess.equals("END")){
								System.out.println("Server has closed the connection.");
								String serverAfterSign = clientSignatureManager.signMessage(mess); 
								// System.out.println("serverAfterSign: " + serverAfterSign);
								byte[] encryptedData = ac.encrypt(serverPublicKey, mess.getBytes());
								dataOut.println(serverAfterSign);
								break;
							}	
							System.out.println("(Decrypted - Valid sig.) - Server says: " + mess);
						}else{
							String mess = out.split(":")[1];
							if (mess.equals("END")){
								System.out.println("Server has closed the connection.");
								String serverAfterSign = clientSignatureManager.signMessage(mess); 
								// System.out.println("serverAfterSign: " + serverAfterSign);
								byte[] encryptedData = ac.encrypt(serverPublicKey, mess.getBytes());
								dataOut.println(serverAfterSign);
								break;
							}	
							System.out.println("(Decrypted - Invalid sig.) - Server says: " + mess);
						}
					}
					//(No encryption, No integrity) Client recieve plaintext
					else{
						if (dataIn.ready()){
							out = dataIn.readLine();
							if (out.equals("END")){
								System.out.println("Server has closed the connection.");
								dataOut.println("END");
								break;
							}			
							System.out.println("Server says: " + out);
						}
					}
				}
			}
		}catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		new Client();
	}
}