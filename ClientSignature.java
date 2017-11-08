import java.io.*;
import java.security.*;
import java.security.spec.*;
import org.bouncycastle.util.encoders.Hex;
import java.nio.charset.Charset;

class ClientSignature {

	// Create a Signature object
	Signature dsa = Signature.getInstance("SHA1withDSA", "SUN"); 

	// ClientSignature constructor
	protected ClientSignature() throws Exception {}

	// Create the public/private key pair for the client here
	protected void initializeClientSignature() 
	throws Exception {

		// Generate the a digital signature key pair
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		keyGen.initialize(1024, random);

		// Get the public and private keys
		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey priv = pair.getPrivate();
		PublicKey pub = pair.getPublic();

		// Initialize the signature with the private key
		dsa.initSign(priv);

		// Save the public key to a file
		byte[] publicKey = pub.getEncoded();
		FileOutputStream keyfos = new FileOutputStream("./Clientcred/clientPublicSignatureKey");
		keyfos.write(publicKey);
		keyfos.close();

	}
	
	protected String signMessage(String message) 
	throws Exception {

		// Update the the signature and sign the data
		byte[] byteMessage = message.getBytes();
		dsa.update(byteMessage);

		// Generate a signature 
		byte[] byteSignature = dsa.sign();
		byte[] hexEncodedArray = Hex.encode(byteSignature);
		String stringSignature = new String(hexEncodedArray, Charset.forName("UTF-8"));

		return stringSignature + ":" + message;
	}

	protected boolean verifyMessage(String serverMessage) 
	throws Exception {

		// Import encoded public key
		FileInputStream keyfis = new FileInputStream("./Servercred/serverPublicSignatureKey");
		byte[] encKey = new byte[keyfis.available()];  
		keyfis.read(encKey);
		keyfis.close();

		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
		KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
		PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

		// Create a signature object and initialize it with the public key
		Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
		sig.initVerify(pubKey);

		String[] splitMessage = serverMessage.split(":");
		String signature = splitMessage[0];
		String message = splitMessage[1];

    // Update the data
		byte[] newMessage = message.getBytes();
		sig.update(newMessage);

		// Convert the signature to a byte array
		byte[] originalSigBytes = Hex.decode(signature.getBytes(Charset.forName("UTF-8")));

		// Verify that signature
		boolean verifies = sig.verify(originalSigBytes);
		return verifies;
	}
}
