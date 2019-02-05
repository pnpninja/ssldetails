package com.github.pnpninja.ssldetails;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

final class ServerHelloSSLv2 {

	private int[] cipherSuites;
	private String serverCertName;
	private String serverCertHash;

	public int[] getCipherSuites() {
		return cipherSuites;
	}

	public String getServerCertName() {
		return serverCertName;
	}

	public String getServerCertHash() {
		return serverCertHash;
	}

	ServerHelloSSLv2(InputStream in)
		throws IOException
	{
		// Record length
		byte[] buf = new byte[2];
		Reader.readFully(in, buf);
		int len = Decryption.dec16be(buf, 0);
		if ((len & 0x8000) == 0) {
			throw new IOException("not a SSLv2 record");
		}
		len &= 0x7FFF;
		if (len < 11) {
			throw new IOException(
				"not a SSLv2 server hello");
		}
		buf = new byte[11];
		Reader.readFully(in, buf);
		if (buf[0] != 0x04) {
			throw new IOException(
				"not a SSLv2 server hello");
		}
		int certLen = Decryption.dec16be(buf, 5);
		int csLen = Decryption.dec16be(buf, 7);
		int connIdLen = Decryption.dec16be(buf, 9);
		if (len != 11 + certLen + csLen + connIdLen) {
			throw new IOException(
				"not a SSLv2 server hello");
		}
		if (csLen == 0 || csLen % 3 != 0) {
			throw new IOException(
				"not a SSLv2 server hello");
		}
		byte[] cert = new byte[certLen];
		Reader.readFully(in, cert);
		byte[] cs = new byte[csLen];
		Reader.readFully(in, cs);
		byte[] connId = new byte[connIdLen];
		Reader.readFully(in, connId);
		cipherSuites = new int[csLen / 3];
		for (int i = 0, j = 0; i < csLen; i += 3, j ++) {
			cipherSuites[j] = Decryption.dec24be(cs, i);
		}
		try {
			CertificateFactory cf =
				CertificateFactory.getInstance("X.509");
			X509Certificate xc =
				(X509Certificate)cf.generateCertificate(
					new ByteArrayInputStream(cert));
			serverCertName =
				xc.getSubjectX500Principal().toString();
			serverCertHash = SHA1Utils.doSHA1(cert);
		} catch (CertificateException e) {
			// ignored
		}
	}
}
