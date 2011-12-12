package org.jdamico.tfa.oath.totp;


import java.lang.reflect.UndeclaredThrowableException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * This is a minimal implementation of the OATH TOTP algorithm.
 * This code is based on RFC6238 (http://tools.ietf.org/html/rfc6238)
 * and it is a derivation from a previous code written by Johan Rydell
 *
 * @author Jose Damico <jd.comment@gmail.com>
 */
public class TotpImpl {
									//  0 1  2   3    4     5      6       7        8
	private final int[] DIGITS_POWER = {1,10,100,1000,10000,100000,1000000,10000000,100000000 };
	private static TotpImpl INSTANCE = null;
	public static TotpImpl getInstance(){
		if(INSTANCE == null) INSTANCE = new TotpImpl();
		return INSTANCE;
	}

	private TotpImpl() {}

	/**
	 * This method uses the JCE to provide the crypto algorithm.
	 * HMAC computes a Hashed Message Authentication Code with the
	 * crypto hash algorithm as a parameter.
	 * @param crypto     the crypto algorithm (HmacSHA1, HmacSHA256, HmacSHA512)
	 * @param keyBytes   the bytes to use for the HMAC key
	 * @param text       the message or text to be authenticated.
	 * @throws UndeclaredThrowableException
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	private byte[] hmac_sha1(String crypto, byte[] keyBytes, byte[] text) throws UndeclaredThrowableException, NoSuchAlgorithmException, InvalidKeyException {
		Mac hmac;
		hmac = Mac.getInstance(crypto);
		SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
		hmac.init(macKey);
		return hmac.doFinal(text);
	}

	/**
	 * This method converts HEX string to byte[]
	 * @param hex   the HEX string
	 * @return      A byte array
	 */
	private byte[] hexStr2Bytes(String hex){
		// Adding one byte to get the right conversion
		// values starting with "0" can be converted
		byte[] bArray = new BigInteger("10" + hex,16).toByteArray();
		// Copy all the REAL bytes, not the "first"
		byte[] ret = new byte[bArray.length - 1];
		for (int i = 0; i < ret.length ; i++) ret[i] = bArray[i+1];
		return ret;
	}

	
	/**
	 * This method generates an TOTP value for the given set of parameters.
	 * @param key   the shared secret
	 * @param time     a value that reflects a time
	 * @param returnDigits     number of digits to return
	 * @return      A numeric String in base 10 that includes truncationDigits digits
	 * @throws NoSuchAlgorithmException 
	 * @throws UndeclaredThrowableException 
	 * @throws InvalidKeyException 
	 */
	public String generateTOTP(byte[] key, String time,  int returnDigits) throws InvalidKeyException, UndeclaredThrowableException, NoSuchAlgorithmException {
		return generateTOTP(key, time, returnDigits, "HmacSHA1");
	}

	public String generateTOTP256(byte[] key, String time,  int returnDigits) throws InvalidKeyException, UndeclaredThrowableException, NoSuchAlgorithmException {
		return generateTOTP(key, time, returnDigits, "HmacSHA256");
	}

	public String generateTOTP512(byte[] key, String time,  int returnDigits) throws InvalidKeyException, UndeclaredThrowableException, NoSuchAlgorithmException {
		return generateTOTP(key, time, returnDigits, "HmacSHA512");
	}
	
	public String generateTOTP(byte[] key, String time, int codeDigits, String crypto) throws InvalidKeyException, UndeclaredThrowableException, NoSuchAlgorithmException {
		
		// Using the counter
		// First 8 bytes are for the movingFactor
		// Complaint with base RFC 4226 (HOTP)

		while(time.length() < 16 ) time += "0";
		byte[] msg = hexStr2Bytes(time); // Get the HEX in a byte[]

		// Adding one byte to get the right conversion

		byte[] hash = hmac_sha1(crypto, key, msg);
		int offset = hash[hash.length - 1] & 0xf; // put selected bytes into result int
		int binary =
				((hash[offset] & 0x7f) << 24) |
				((hash[offset + 1] & 0xff) << 16) |
				((hash[offset + 2] & 0xff) << 8) |
				(hash[offset + 3] & 0xff);
		int otp = binary % DIGITS_POWER[codeDigits];
		String result = Integer.toString(otp);
		while (result.length() < codeDigits) result += "0";
		return result;
	}
}