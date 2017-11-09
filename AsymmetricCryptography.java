
//
// ***************************************************************************************
// Modified by: Ben Wolfe (V00205547) and Daniel Olaya (V00855054)
// Course: SENG360 - Security Engineering
// Date: November, 2017
// Assignment 3 - Chat program that allows to users to communicate using different 
// security parameters such as encryption, integrity (digital signatures) and mutual authentication.
// ***************************************************************************************
//

// Asymmetric encryption implementation as per documentation
// https://stackoverflow.com/questions/31915617/how-to-encrypt-string-with-public-key-and-decrypt-with-private-key/39615507

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.io.*;
import java.nio.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;

// Helper class used to create and manage private and public keys, encrypt and decrypt messages.
public class AsymmetricCryptography {

    private static final String ALGORITHM = "RSA";

    public static byte[] encrypt(byte[] publicKey, byte[] inputData) throws Exception {

        PublicKey key = KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(publicKey));
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.PUBLIC_KEY, key);
        byte[] encryptedBytes = cipher.doFinal(inputData);
        return encryptedBytes;
    }

    public static byte[] decrypt(byte[] privateKey, byte[] inputData) throws Exception {

        PrivateKey key = KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.PRIVATE_KEY, key);
        byte[] decryptedBytes = cipher.doFinal(inputData);
        return decryptedBytes;
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");

        // 512 is keysize
        keyGen.initialize(512, random);
        KeyPair generateKeyPair = keyGen.generateKeyPair();
        return generateKeyPair;
    }

    public static void writeToFile(String path, byte[] key) throws IOException {
    	File f = new File(path);
    	f.getParentFile().mkdirs();

    	FileOutputStream fos = new FileOutputStream(f);
    	fos.write(key);
    	fos.flush();
    	fos.close();
    }

    // Helper method used to load existing keys from a file
    // https://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file
    public static PrivateKey getPrivate (String filename) throws Exception {

      byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

      PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return kf.generatePrivate(spec);
    }

    // Helper method used to load existing keys from a file
    // https://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file
    public static PublicKey getPublic(String filename) throws Exception {

      byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

      X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return kf.generatePublic(spec);
    }

    public static void main(String[] args) throws Exception {

        // KeyPair generateKeyPair = generateKeyPair();

        // byte[] publicKey = generateKeyPair.getPublic().getEncoded();
        // byte[] privateKey = generateKeyPair.getPrivate().getEncoded();

        // writeToFile("./Clientcred/clientRSApublicKey", publicKey);
        // writeToFile("./Clientcred/clientRSAprivateKey", privateKey);

    	byte[] privateKey = getPrivate("./Clientcred/clientRSAprivateKey").getEncoded();
    	byte[] publicKey = getPublic("./Clientcred/clientRSApublicKey").getEncoded();



        byte[] encryptedData = encrypt(publicKey, "howdy this is Visruth here".getBytes());
        System.out.println("Encrypted message:" + encryptedData);
        byte[] decryptedData = decrypt(privateKey, encryptedData);
        System.out.println("Decrypted message:" + new String(decryptedData));

    }
}