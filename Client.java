import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;


public class Client implements Runnable {

	private String settings; //chatAt(0) = encr, (1) = integrity, (2) = authentication
	BufferedReader br1, br2;
	PrintWriter pr1;
	Socket socket;
	Thread t1, t2;
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

	private static void authenticate(Scanner scanner, PrintWriter pr1, BufferedReader br2){
		System.out.println("LOGIN: Please enter your username:");
		String userName = scanner.nextLine();
		pr1.println(userName);
		System.out.println("LOGIN: Please enter your password:");
		String pass = scanner.nextLine();
		try{
			pr1.println(bytesToHex(hash(pass)));
			String access = br2.readLine();
			if (access.equals("false")){
				System.out.println();
				System.out.println("Authentication - Wrong user or password, terminating connection.");
				System.exit(1);
			}
			System.out.println("Authentication - Login validation successful.");
		}catch(Exception e){
			e.printStackTrace();
			System.out.println("Hash - Error while hashing the string");
		}

	}


	public Client() {
		try {
			Scanner scanner = new Scanner(System.in);
			// settings = chatSettings(scanner);
			settings = "101";
			System.out.println("Client chat settings: " +settings );

			socket = new Socket("localhost", 5000);

			br1 = new BufferedReader(new InputStreamReader(System.in));
			br2 = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			pr1 = new PrintWriter(socket.getOutputStream(), true);

			//Login process
			authenticate(scanner, pr1, br2);
			
			//Chat settings validation
			pr1.println(settings);
			String sett = br2.readLine();
			if (sett.equals("false")){
				System.out.println("Settings - Error, different settings selected from Client, terminating program.");
				System.exit(1);
			}
			System.out.println("Settings - Options verified, Starting conversation. . . .");
			System.out.println("*****************");
			
			//Initiate chat
			t1 = new Thread(this);
			t2 = new Thread(this);
			t1.start();
			t2.start();

		} catch (Exception e) {
		}
	}

	public void run() {
		try {


			if (Thread.currentThread() == t2) {
				//Client chat                 
				while (true){
					in = br1.readLine();
					if (in.equals("END")){
						System.out.println("Chat has ended.");
						pr1.println("END");
						System.exit(1);
					}
					pr1.println(in);
				}
			}else {
				while(true) {
					out = br2.readLine();
					if (out.equals("END")){
						System.out.println("Server has closed the connection.");
						System.exit(1);

					}
					System.out.println("Server says : : : " + out);
				}
			}
		}catch (Exception e) {
		}

	}

	 public static void main(String[] args) {
		new Client();
	}
}