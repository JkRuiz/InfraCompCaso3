package server;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/* 
 * Este servidor usa funciones de la libreria Bouncy Castle. 
 * 
 * Copyright (c) 2000 - 2017 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
 * subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all copies or substantial 
 * portions of the Software.
 */

public class Seguridad {
	public static final String RSA = "RSA";

	public static final String HMACMD5 = "HMACMD5";

	public static final String HMACSHA1 = "HMACSHA1";

	public static final String HMACSHA256 = "HMACSHA256";

	public static final String RC4 = "RC4";

	public static final String BLOWFISH = "BLOWFISH";

	public static final String AES = "AES";

	public static final String DES = "DES";

	public Seguridad() {
	}

	public static byte[] sE(byte[] msg, Key key, String algo)
			throws IllegalBlockSizeException, BadPaddingException,
			InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		algo = algo
				+ ((algo.equals(DES)) || (algo.equals(AES)) ? "/ECB/PKCS5Padding" : "");
		Cipher decifrador = Cipher.getInstance(algo);
		decifrador.init(1, key);
		return decifrador.doFinal(msg);
	}

	public static byte[] sD(byte[] msg, Key key, String algo)
			throws IllegalBlockSizeException, BadPaddingException,
			InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		algo = algo
				+ ((algo.equals(DES)) || (algo.equals(AES)) ? "/ECB/PKCS5Padding" : "");
		Cipher decifrador = Cipher.getInstance(algo);
		decifrador.init(2, key);
		return decifrador.doFinal(msg);
	}

	public static byte[] aE(byte[] msg, Key key, String algo)
			throws IllegalBlockSizeException, BadPaddingException,
			InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher decifrador = Cipher.getInstance(algo);
		decifrador.init(1, key);
		return decifrador.doFinal(msg);
	}

	public static byte[] aD(byte[] msg, Key key, String algo)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher decifrador = Cipher.getInstance(algo);
		decifrador.init(2, key);
		return decifrador.doFinal(msg);
	}

	public static byte[] hD(byte[] msg, Key key, String algo)
			throws NoSuchAlgorithmException, InvalidKeyException,
			IllegalStateException, UnsupportedEncodingException {
		Mac mac = Mac.getInstance(algo);
		mac.init(key);

		byte[] bytes = mac.doFinal(msg);
		return bytes;
	}

	public static boolean verifyIntegrity(byte[] msg, Key key, String algo,
			byte[] hash) throws Exception {
		byte[] nuevo = hD(msg, key, algo);
		if (nuevo.length != hash.length) {
			return false;
		}
		for (int i = 0; i < nuevo.length; i++) {
			if (nuevo[i] != hash[i])
				return false;
		}
		return true;
	}

	public static SecretKey keyGenGenerator(String algoritmo)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		int tamLlave = 0;
		if (algoritmo.equals(DES)) {
			tamLlave = 64;
		} else if (algoritmo.equals(AES)) {
			tamLlave = 128;
		} else if (algoritmo.equals(BLOWFISH)) {
			tamLlave = 128;
		} else if (algoritmo.equals(RC4)) {
			tamLlave = 128;
		}
		if (tamLlave == 0) {
			throw new NoSuchAlgorithmException();
		}

		KeyGenerator keyGen = KeyGenerator.getInstance(algoritmo);
		keyGen.init(tamLlave);
		SecretKey key = keyGen.generateKey();
		return key;
	}

	public static X509Certificate generateV3Certificate(KeyPair pair)
			throws Exception {
		// Generate self-signed certificate
		X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		nameBuilder.addRDN(BCStyle.OU, "OU");
		nameBuilder.addRDN(BCStyle.O, "O");
		nameBuilder.addRDN(BCStyle.CN, "CN");

		String stringDate1 = "2016-10-01";
		String stringDate2 = "2020-12-20";
		DateFormat format = new SimpleDateFormat("yyyy-MM-dd");
		Date notBefore = null;
		Date notAfter = null;
		try {
			notBefore = format.parse(stringDate1);
			notAfter = format.parse(stringDate2);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		BigInteger serialNumber = new BigInteger(128, new Random());

		X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
				nameBuilder.build(), serialNumber, notBefore, notAfter,
				nameBuilder.build(), pair.getPublic());
		X509Certificate certificate = null;
		try {
			ContentSigner contentSigner = new JcaContentSignerBuilder(
					"SHA256WithRSAEncryption").build(pair.getPrivate());

			certificate = new JcaX509CertificateConverter()
					.getCertificate(certificateBuilder.build(contentSigner));
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		}
		return certificate;
	}

	public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance(RSA);
		kpGen.initialize(1024, new SecureRandom());
		return kpGen.generateKeyPair();
	}
}
