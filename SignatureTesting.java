
import java.io.*;
import java.security.*;
import java.security.spec.*;
import org.bouncycastle.util.encoders.Hex;
import java.nio.charset.Charset;

class SignatureTesting {

	public static void main (String[] args) 
	throws Exception {


// Initialize the client and server signatures.  This will only be done once per session (the files will be
// automatically overwrite each session)
		ClientSignature clientSignatureManager = new ClientSignature();
		ServerSignature serverSignatureManager = new ServerSignature();

		clientSignatureManager.initializeClientSignature();
		serverSignatureManager.initializeServerSignature();


// CLIENT SIDE
		String clientBeforeSign = "Hey, server!";
		String clientAfterSign = clientSignatureManager.signMessage(clientBeforeSign); // <- Message clientAfterSign is sent over chat
		

// Validating message integrity on the server side
		boolean validateClientSignature = serverSignatureManager.verifyMessage(clientAfterSign);
		if (validateClientSignature) {
			System.out.print("Valid signature...");
			String message = clientAfterSign.split(":")[1];
			System.out.println("Client: " + message);
		}

		// SERVER SIDE - Sending a response
		String serverBeforeSign = "Hey, client!";
		String serverAfterSign = serverSignatureManager.signMessage(serverBeforeSign); // <- Message serverAfterSign is sent over chat


// Validating message integrity on the client side
		boolean validateServerSignature = clientSignatureManager.verifyMessage(serverAfterSign);
		if (validateServerSignature) {
			System.out.print("Valid signature..." + validateServerSignature);
			String message = serverAfterSign.split(":")[1];
			System.out.println("Server: " + message);
		}
	}
	
}