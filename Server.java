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
import java.security.*;
import java.security.spec.*;
import org.bouncycastle.util.encoders.Hex;
import java.nio.charset.Charset;

// Implements the Server program, always running and waiting for client to innitiate connection in port 5000.
public class Server implements Runnable {

	protected String settings; //charAt(0) = encr, (1) = integrity, (2) = authentication
	BufferedReader console, dataIn;
	PrintWriter dataOut;
	DataOutputStream dOut; //used for sending byte[] (Encryption)
	DataInputStream dIn; //used for sending byte[] (Encryption)

	Thread sending, receiving;
	ServerSocket serversocket = null;
	boolean authentFlag, 
		integFlag,
		encrypFlag,
		validConnection;

	String in="",out="", clientSett = "";
	protected Socket socket;
	protected ServerSignature serverSignatureManager;
	protected AsymmetricCryptography ac;
	private byte[] serverPrivateKey, clientPublicKey;

	// Retreives user settings and appends result to string 'settings' which is later
	// used to compare with Client settings.
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

	//Method used to compare Server and Client settings, if settings match, 'true' is returned 
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

    // Method used to receive client username and hashed password. If username exists on the credential.txt
    // database, then the password given by client will be hashed with the salt (utoken[1]). If the result
    // es equal to h(salt + h(pass)), then it is a valid password and 'true' will be returned.
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
					String preHash = utoken[1] + pass; //password hashed with salt
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

	public Server() {
		Scanner scanner = new Scanner(System.in);
		while (true){
			clientSett = "";
			authentFlag = false; integFlag = false; encrypFlag = false;
			System.out.println("\n===========SERVER INITIALIZED===========");

			try{
				//Setting up connection
				validConnection = true;
				serversocket = new ServerSocket(5000);
				System.out.println("Waiting for client to connect...");
				socket = serversocket.accept();
				System.out.println("Client connected with Ip: " +socket.getInetAddress().getHostAddress());

				console = new BufferedReader(new InputStreamReader(System.in));
				dataOut = new PrintWriter(socket.getOutputStream(), true);
				dataIn = new BufferedReader(new InputStreamReader(socket.getInputStream()));

				//Settings parameters
				if (validConnection){
					System.out.println("\n===========SETTINGS VALIDATION===========");

					// settings ="110";  //[0] Encryp, [1] Integ, [2] Auth
					settings = chatSettings(scanner);
					validateSettings(settings, dataIn); 	
				}

				//Authentication process
				if (validConnection && authentFlag){
					System.out.println("Settings - Chat settings verified");
					System.out.println("\n===========AUTHENTICATION===========");
					//Client authentication with Server
					boolean validCredential = validUser(dataOut, dataIn); 
					if (!validCredential){
						validConnection = false;
					    System.out.println("Authentication - Wrong user or password, terminating connection.");
					}
					//Server authentication with client
					System.out.println("Client credentials verified, please provide Server credentials...");
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

				// Integrity parameters - Initializes server signatures. 
				// This will only be done once per session (the files will be automatically overwrite each session)
				if (validConnection && (integFlag || encrypFlag)){
					System.out.println("\n===========GENERATING SIGNATURE KEYS===========");

					serverSignatureManager = new ServerSignature();
					serverSignatureManager.initializeServerSignature();
					System.out.println("Signature keys intialization completed...");
				}

				// Enctryption parameters
				if (validConnection && encrypFlag){
					System.out.println("\n===========RETRIEVING ENCRYPTION KEYS===========");
					System.out.println("Retrieving public and private keys...");
					//Loading exiting client RSA public keys and server RSA private key
					ac = new AsymmetricCryptography();
					serverPrivateKey = ac.getPrivate("./Servercred/serverRSAprivateKey").getEncoded();
					clientPublicKey = ac.getPublic("./Servercred/clientRSApublicKey").getEncoded();
					//Used for sending byte array
					dOut = new DataOutputStream(socket.getOutputStream());
					dIn = new DataInputStream(socket.getInputStream());
				}
				//Initiate conversation (threads)
				if (validConnection ){
					System.out.println("\n===========CHAT INITIATED===========");
					sending = new Thread(this);
					receiving = new Thread(this);
					sending.start();
					receiving.start();
					sending.join();
					receiving.join();
					System.out.println("===========END OF CHAT===========");
				}

				System.out.println("Restarting server...");
				serversocket.close();
				socket.close();

			} catch (Exception e) {
			    e.printStackTrace();
        	}
		}
	}

	public void run() {
		try {
			// Server sending thread
			if (Thread.currentThread() == sending) {
				while(true) {
					// Checks if client thread is still running
					sending.sleep(500);
					if (!receiving.isAlive()){
					 	break;
					}
					// Server send message
					if (console.ready()){
						in = console.readLine();
						if (in.equals("END")){
							if (encrypFlag && !integFlag){
								byte[] encryptedData = ac.encrypt(clientPublicKey, in.getBytes());
								dOut.writeInt(encryptedData.length);
								dOut.write(encryptedData);
								break;
							}else if (encrypFlag && integFlag){
								String serverAfterSign = serverSignatureManager.signMessage(in); 
								// System.out.println("serverAfterSign: " + serverAfterSign);
								byte[] encryptedData = ac.encrypt(clientPublicKey, in.getBytes());
								dataOut.println(serverAfterSign);
								break;
							}else{
								dataOut.println("END");
								break;
							}
						} 
						// (Integrity only) Server send
						if (integFlag && !encrypFlag){
							String serverAfterSign = serverSignatureManager.signMessage(in); 
							dataOut.println(serverAfterSign);
						}

						//(Encryption only) Server send
						else if (!integFlag && encrypFlag) {
							byte[] encryptedData = ac.encrypt(clientPublicKey, in.getBytes());
							// System.out.println("Sending: " + in + ", encrypted message: " + encryptedData);
							dOut.writeInt(encryptedData.length);
							dOut.write(encryptedData);
						}
						//(Encryption and Integrity) Server send
						else if (integFlag && encrypFlag){
							String serverAfterSign = serverSignatureManager.signMessage(in); 
							// System.out.println("serverAfterSign: " + serverAfterSign);
							byte[] encryptedData = ac.encrypt(clientPublicKey, in.getBytes());
							dataOut.println(serverAfterSign);

						}
						// (No encryption, No integrity) - Server send plaintext
						else{
							dataOut.println(in);
						}
					}
				} 

			//Server receiving thread
			} else {
				while(true) {
					//(Integrity only) 
					if (!encrypFlag && integFlag){
						if (dataIn.ready()){
							out = dataIn.readLine();
							// Check if end of communication
							if (out.equals("END")){
								System.out.println("Connection has been terminated");			
								break;
							}
							// (Integrity only) Server recieve
							if (integFlag){
								boolean validateClientSignature = serverSignatureManager.verifyMessage(out);
								if (validateClientSignature) {
									String message = out.split(":")[1];
									System.out.println("(Valid Sig) - Client says: " + message);
								}else{
									String message = out.split(":")[1];
									System.out.println("(Invalid Sig) - Client says: " + message);
								}
							}
						}
					}
					// (Encryption only) Server recieve - DataStreams used to send binary data
					else if (!integFlag && encrypFlag) {
						int length = dIn.readInt(); 
						byte[] message = new byte[length];
						
						if(length>0) {
						    dIn.readFully(message, 0, message.length); 
						}
						byte[] decryptedData = ac.decrypt(serverPrivateKey, message);
						String decrypt = new String(decryptedData);

						if (decrypt.equals("END")){
							System.out.println("Client has closed the connection.");
							byte[] encryptedData = ac.encrypt(clientPublicKey, decrypt.getBytes());
							dOut.writeInt(encryptedData.length);
							dOut.write(encryptedData);
							break;
						}
						System.out.println("(Decrypted message) - Client says: " + decrypt);
					}
					//(Encryption and Integrity)
					else if (encrypFlag && integFlag){
						out = dataIn.readLine();
						boolean validateServerSignature = serverSignatureManager.verifyMessage(out);
						if (validateServerSignature) {
							String mess = out.split(":")[1]; 
							if (mess.equals("END")){
								System.out.println("Server has closed the connection.");
								String serverAfterSign = serverSignatureManager.signMessage(mess); 
								// System.out.println("serverAfterSign: " + serverAfterSign);
								byte[] encryptedData = ac.encrypt(clientPublicKey, mess.getBytes());
								dataOut.println(serverAfterSign);
								break;
							}	
							System.out.println("(Decrypted - Valid sig.) - Server says: " + mess);
						}else{
							String mess = out.split(":")[1];
							if (mess.equals("END")){
								System.out.println("Server has closed the connection.");
								String serverAfterSign = serverSignatureManager.signMessage(mess); 
								// System.out.println("serverAfterSign: " + serverAfterSign);
								byte[] encryptedData = ac.encrypt(clientPublicKey, mess.getBytes());
								dataOut.println(serverAfterSign);
								break;
							}
							System.out.println("(Decrypted - Invalid sig.) - Server says: " + mess);
						}
					}
					//(No encryption, No integrity) Server receive plaintext
					else{
						if (dataIn.ready()){
							out = dataIn.readLine();
							if (out.equals("END")){
								System.out.println("Server has closed the connection.");
								dataOut.println("END");
								break;
							}					
							System.out.println("Client says: " + out);
						}
					}
				} 
			}
		}catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		new Server();
	}
}