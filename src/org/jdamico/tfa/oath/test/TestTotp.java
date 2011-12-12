package org.jdamico.tfa.oath.test;

import static org.junit.Assert.*;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.jdamico.tfa.oath.totp.TotpImpl;
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
		unixTime = 59;//System.currentTimeMillis() / 1000L;
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

}
