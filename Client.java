import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.*;
import java.util.*;

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

public Client() {
    try {
        // Scanner scanner = new Scanner(System.in);
        // settings = chatSettings(scanner);
        settings = "111";
        System.out.println("Client chat settings: " +settings );

        t1 = new Thread(this);
        t2 = new Thread(this);
        socket = new Socket("localhost", 5000);

        br1 = new BufferedReader(new InputStreamReader(System.in));
        br2 = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        pr1 = new PrintWriter(socket.getOutputStream(), true);

        pr1.println(settings);
        
        System.out.println("Settings verified, conversation started. . . .");
        System.out.println("*****************");
        t1.start();
        t2.start();

    } catch (Exception e) {
    }
}

public void run() {
    try {




        if (Thread.currentThread() == t2) {
            //sending chat settings

            while (true){
                in = br1.readLine();
                if (in.equals("END")){
                    System.out.println("Chat has ended.");
                    pr1.println("END");
                    System.exit(1);
                }
                pr1.println(in);
            } 
        } else {
            while(true) {
                out = br2.readLine();
                if (out.equals("END")){
                    System.out.println("Server has closed the connection.");
                    System.exit(1);

                }
                System.out.println("Server says : : : " + out);
            }
        }
    } catch (Exception e) {
    }

 }

 public static void main(String[] args) {
     new Client();
 }
 }