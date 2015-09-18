package Chat;

import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import javax.xml.bind.DatatypeConverter;

import java.io.Serializable;

class Tools{

    public static String hmac(String key, String data) throws Exception {
    	Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
    	SecretKeySpec secret_key = new SecretKeySpec(key.getBytes(), "HmacSHA256");
    	sha256_HMAC.init(secret_key);

    	return DatatypeConverter.printHexBinary(sha256_HMAC.doFinal(data.getBytes()));
    }

    public static String encryptRSA(PublicKey key,String text) throws Exception {
    	byte[] cipherText = null;
		final Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		cipherText = cipher.doFinal(text.getBytes());
    	return DatatypeConverter.printHexBinary(cipherText);
    }



	public static String decryptRSA(PrivateKey key,String text) throws Exception {
		byte[] cipherText = DatatypeConverter.parseHexBinary(text);
		byte[] plainText = null;
		// get an RSA cipher object and print the provider
		final Cipher cipher = Cipher.getInstance("RSA");

		// decrypt the text using the private key
		cipher.init(Cipher.DECRYPT_MODE, key);
		plainText = cipher.doFinal(cipherText);

		return new String(plainText);
	}


    public static String encryptAES(String key, String data) throws Exception {
    	SecretKeySpec spec = new SecretKeySpec(key.getBytes(),"AES");

    	byte[] cipherText = null;
		final Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, spec);
		cipherText = cipher.doFinal(data.getBytes());
    	return DatatypeConverter.printHexBinary(cipherText);
    }

    public static String decryptAES(String key, String data) throws Exception {
    	SecretKeySpec spec = new SecretKeySpec(key.getBytes(),"AES");

    	byte[] cipherText = DatatypeConverter.parseHexBinary(key);
    	byte[] plainText = null;
		final Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, spec);
		plainText = cipher.doFinal(cipherText);
    	return new String(plainText);
    }
    
}