
import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;

public class Server implements Runnable {

	private String settings; //charAt(0) = encr, (1) = integrity, (2) = authentication
	ServerSocket serversocket;
	BufferedReader br1, br2;
	PrintWriter pr1;
	Socket socket;
	Thread t1, t2;
	String in="",out="";

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


	private static boolean authenticate(String user, String pass){
		boolean found = false;
		String [] utoken = null;

		System.out.println("Authentication - user: "+ user + " passhash:"+ pass);

		try{
			File file = new File ("credentials.txt");
			Scanner scanner = new Scanner (file);
			while (scanner.hasNextLine()){
				utoken = scanner.nextLine().split(" ");
				if (utoken[0].equals(user)){
					found = true;
				}
				if (found){
					String preHash = utoken[1] + pass;
					String postHash = bytesToHex(hash(preHash));
					if (postHash.equals(utoken[2])){
						return true;
					}
				}
			}
		}catch (NullPointerException e){
			e.printStackTrace();
			System.out.println("Autentication ERROR - Error reading credential file");
		}catch (FileNotFoundException e){
			e.printStackTrace();
			System.out.println("Autentication ERROR - Credential file does not exist");
		}catch (Exception e){
			e.printStackTrace();
			System.out.println("Autentication ERROR - Problem hashing password");
		}


		return false;
	}


	public Server() {
		String clientSett;

		try {
			Scanner scanner = new Scanner(System.in);
			// settings = chatSettings(scanner);
			settings ="111";    
			System.out.println("Server chat settings: " +settings );

			serversocket = new ServerSocket(5000);
			System.out.println("Server is waiting. . . . ");
			socket = serversocket.accept();
			System.out.println("Client connected with Ip: " +socket.getInetAddress().getHostAddress());



			br1 = new BufferedReader(new InputStreamReader(System.in));
			pr1 = new PrintWriter(socket.getOutputStream(), true);
			br2 = new BufferedReader(new InputStreamReader(socket.getInputStream()));


			//Authenticate user
			String user = br2.readLine();
			String pass = br2.readLine();
			boolean access = authenticate(user, pass);
			if (!access){
				System.out.println("Authentication - Wrong user name of password, terminating connection.");
				pr1.println("false");
				// pr1.println("END");
				System.exit(1);
			}else{
				System.out.println("Authentication - Succesful authentication.");
				pr1.println("true");
			}


			//Chat settings validation
			clientSett = br2.readLine();
			System.out.println("Client settings: "+ clientSett);
			if (!clientSett.equals(settings)){
				System.out.println("Settings - Error, different settings selected from Client, terminating program.");
				pr1.println("false");
				System.exit(1);
			}
			System.out.println("Settings - Options verified, Starting conversation. . . .");
			System.out.println("*****************");



		} catch (Exception e) {
			System.exit(1);
		}


			//Initiate chat

			t1 = new Thread(this);
			t2 = new Thread(this);
			t1.start();
			t2.start();
	}

	public void run() {
		try {


			if (Thread.currentThread() == t1) {

				//server input
				while(true) {
					in = br1.readLine();
					if (in.equals("END")){
						System.out.println("Chat has ended.");
						pr1.println("END");
						System.exit(1);
					}
					pr1.println(in);
				} 

			//client input
			} else {
				while(true) {
					out = br2.readLine();
					if (out.equals("END")){
						System.out.println("Client has closed the connection.");
						System.exit(1);
					}
					System.out.println("Client says : : : " + out);
				} 
			}

		}catch (Exception e) {
			 // e.printStackTrace();
			System.exit(1);

		}
	}

	public static void main(String[] args) {
		new Server();
	}
}