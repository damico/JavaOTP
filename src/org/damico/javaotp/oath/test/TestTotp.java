package org.damico.javaotp.oath.test;

import java.lang.reflect.UndeclaredThrowableException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.damico.javaotp.oath.totp.TotpImpl;
import org.junit.Before;
import org.junit.Test;

public class TestTotp {
	
	private byte[] 	seed		 = null;
	private long 	t0			 = -1;
	private long 	x			 = -1;
	private long 	unixTime	 = -1;
	private String 	steps		 = null;
	private int 	size		 = -1;

	@Before
	public void setUp() throws Exception {
		seed	 = new byte[]{10,20,30,40,60,80,90,00,10,20,30,40,60,80,90,00};
		t0		 = 0;
		x		 = 30;
		unixTime = System.currentTimeMillis() / 1000L;
		steps	 = "0";
		size	 = 6;
	}

	@Test
	public void test() {

		try{
				long T = (unixTime - t0)/x;
				steps = Long.toHexString(T).toUpperCase();
				while(steps.length() < 16) steps = "0" + steps;
				
				System.out.println(TotpImpl.getInstance().generateTOTP(seed, steps, size, "HmacSHA1") + "\t SHA1");
				System.out.println(TotpImpl.getInstance().generateTOTP(seed, steps, size, "HmacSHA256") + "\t SHA256");
				System.out.println(TotpImpl.getInstance().generateTOTP(seed, steps, size, "HmacSHA512") + "\t SHA512");

		}catch (final Exception e){
			System.out.println("Error : " + e);
		}
	}

	
	@Test
	public void TestOtpWindow(){	
		
		int windowMinutes = 5;
		
		Map<String,Long> otpWindowMap = new HashMap<String, Long>();
		long backwardWindow = unixTime - (x*windowMinutes);
		long forwardWindow =  unixTime + (x*windowMinutes);
		otpWindowMap.put(genOtp(unixTime, size, seed),unixTime);
		for (long i = backwardWindow; i <= forwardWindow; i++) otpWindowMap.put(genOtp(i, size, seed),i);
		
		Iterator<String> iter = otpWindowMap.keySet().iterator();
		while(iter.hasNext()){
			String otp = iter.next();
			Date date = new Date(otpWindowMap.get(otp) * 1000);
			SimpleDateFormat formatter = new SimpleDateFormat("[MM/dd/yyyy - H:m:s] ");
			String strTime = formatter.format(date);
			System.out.println(strTime+otp);
		}
	}
	
	private String genOtp(long baseTime, int size, byte[] seed) {
		String otpGen = null;
		String steps	 = "0";
		long t0		 = 0;
		long x		 = 30;
		long T = (baseTime - t0)/x;
		steps = Long.toHexString(T).toUpperCase();
		while(steps.length() < 16) steps = "0" + steps;
		
		try {
			otpGen = TotpImpl.getInstance().generateTOTP(seed, steps, size, "HmacSHA1");
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (UndeclaredThrowableException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		
		return otpGen;
	}
	
}
