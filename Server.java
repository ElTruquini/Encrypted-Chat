
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.*;
import java.util.*;

public class Server implements Runnable {

    private String settings; //chatAt(0) = encr, (1) = integrity, (2) = authentication
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
public Server() {
    String clientSett;

    try {
        // Scanner scanner = new Scanner(System.in);
        // settings = chatSettings(scanner);
        settings ="111";
        System.out.println("Server chat settings: " +settings );

        t1 = new Thread(this);
        t2 = new Thread(this);
        serversocket = new ServerSocket(5000);
        System.out.println("Server is waiting. . . . ");
        socket = serversocket.accept();
        System.out.println("Client connected with Ip: " +socket.getInetAddress().getHostAddress());



        br1 = new BufferedReader(new InputStreamReader(System.in));
        pr1 = new PrintWriter(socket.getOutputStream(), true);
        br2 = new BufferedReader(new InputStreamReader(socket.getInputStream()));



        //Chat settings
        clientSett = br2.readLine();
        System.out.println("Client settings: "+ clientSett);
        if (!clientSett.equals(settings)){
            System.out.println("ERROR - Different settings selected by Client, terminating program.");
            pr1.println("ERROR - Different settings selected by Server, terminating program.");
            pr1.println("END");
            System.exit(1);
        }

        t1.start();
        t2.start();


    } catch (Exception e) {
    }
 }

 public void run() {
    try {


        if (Thread.currentThread() == t1) {

            System.out.println("Settings verified, conversation started. . . .");
            System.out.println("*****************");
            //server chat
            while(true) {
                in = br1.readLine();
                if (in.equals("END")){
                    System.out.println("Chat has ended.");
                    pr1.println("END");
                    System.exit(1);
                }
                pr1.println(in);
            } 

        //client chat
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