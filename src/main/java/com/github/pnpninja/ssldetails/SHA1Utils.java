package com.github.pnpninja.ssldetails;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

public final class SHA1Utils {

	/*
	 * Compute the SHA-1 hash of some bytes, returning the hash
	 * value in hexadecimal.
	 */
	static String doSHA1(byte[] buf)
	{
		return doSHA1(buf, 0, buf.length);
	}

	static String doSHA1(byte[] buf, int off, int len)
	{
		try {
			MessageDigest md = MessageDigest.getInstance("SHA1");
			md.update(buf, off, len);
			byte[] hv = md.digest();
			Formatter f = new Formatter();
			for (byte b : hv) {
				f.format("%02x", b & 0xFF);
			}
			return f.toString();
		} catch (NoSuchAlgorithmException nsae) {
			throw new Error(nsae);
		}
	}
}
