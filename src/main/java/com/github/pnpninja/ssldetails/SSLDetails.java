package com.github.pnpninja.ssldetails;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;


public class SSLDetails {
		
	private static final SecureRandom RNG = new SecureRandom();
	
	
	
	static void usage()
	{
		System.err.println("usage: TestSSLServer servername [ port ]");
		System.exit(1);
	}
	
	private static void addCipherSuiteDetails(List<CipherSuite> cipherSuite,int suite) {
		CipherSuite cs = Constants.CIPHER_SUITES.get(suite);
		if (cs != null) {
			cipherSuite.add(cs);
		} 
	}
	
	public static List<CipherSuite> getCipherSuites(String name,int port,Proxy proxy){
		List<CipherSuite> cipherSuites = new ArrayList<CipherSuite>();
		InetSocketAddress isa = new InetSocketAddress(name, port);

		Set<Integer> sv = new TreeSet<Integer>();
		boolean compress = false;
		for (int v = 0x0300; v <= 0x0303; v ++) {
			ServerHello sh = connect(isa,
				v, Constants.CIPHER_SUITES.keySet(),proxy);
			if (sh == null) {
				continue;
			}
			sv.add(sh.getProtoVersion());
			if (sh.getCompression() == 1) {
				compress = true;
			}
		}

		ServerHelloSSLv2 sh2 = connectV2(isa,proxy);

		if (sh2 != null) {
			sv.add(0x0200);
		}

		if (sv.size() == 0) {
			return cipherSuites;
		}

		Set<Integer> lastSuppCS = null;
		Map<Integer, Set<Integer>> suppCS =
			new TreeMap<Integer, Set<Integer>>();
		Set<String> certID = new TreeSet<String>();

		if (sh2 != null) {
			Set<Integer> vc2 = new TreeSet<Integer>();
			for (int c : sh2.getCipherSuites()) {
				addCipherSuiteDetails(cipherSuites, c);
			}
		}

		for (int v : sv) {
			if (v == 0x0200) {
				continue;
			}
			Set<Integer> vsc = supportedSuites(isa, v, certID,proxy);
			suppCS.put(v, vsc);
			if (lastSuppCS == null || !lastSuppCS.equals(vsc)) {
				for (int c : vsc) {
					addCipherSuiteDetails(cipherSuites, c);
				}
				lastSuppCS = vsc;
			}
		}
		return cipherSuites;
	}
	

	public static void printSSLDetails(String name, int port,Proxy proxy) {
		
		InetSocketAddress isa = new InetSocketAddress(name, port);

		Set<Integer> sv = new TreeSet<Integer>();
		boolean compress = false;
		for (int v = 0x0300; v <= 0x0303; v ++) {
			ServerHello sh = connect(isa,
				v, Constants.CIPHER_SUITES.keySet(),proxy);
			if (sh == null) {
				continue;
			}
			sv.add(sh.getProtoVersion());
			if (sh.getCompression() == 1) {
				compress = true;
			}
		}

		ServerHelloSSLv2 sh2 = connectV2(isa,proxy);

		if (sh2 != null) {
			sv.add(0x0200);
		}

		if (sv.size() == 0) {
			System.out.println("No SSL/TLS server at " + isa);
			System.exit(1);
		}
		System.out.print("Supported versions:");
		for (int v : sv) {
			System.out.print(" ");
			System.out.print(versionString(v));
		}
		System.out.println();
		System.out.println("Deflate compression: "
			+ (compress ? "YES" : "no"));

		System.out.println("Supported cipher suites"
			+ " (ORDER IS NOT SIGNIFICANT):");
		Set<Integer> lastSuppCS = null;
		Map<Integer, Set<Integer>> suppCS =
			new TreeMap<Integer, Set<Integer>>();
		Set<String> certID = new TreeSet<String>();

		if (sh2 != null) {
			System.out.println("  " + versionString(0x0200));
			Set<Integer> vc2 = new TreeSet<Integer>();
			for (int c : sh2.getCipherSuites()) {
				vc2.add(c);
			}
			for (int c : vc2) {
				System.out.println("     "
					+ cipherSuiteStringV2(c));
			}
			suppCS.put(0x0200, vc2);
			if (sh2.getServerCertName() != null) {
				certID.add(sh2.getServerCertHash()
					+ ": " + sh2.getServerCertName());
				
			}
		}

		for (int v : sv) {
			if (v == 0x0200) {
				continue;
			}
			Set<Integer> vsc = supportedSuites(isa, v, certID,proxy);
			suppCS.put(v, vsc);
			if (lastSuppCS == null || !lastSuppCS.equals(vsc)) {
				System.out.println("  " + versionString(v));
				for (int c : vsc) {
					System.out.println("     "
						+ cipherSuiteString(c));
				}
				lastSuppCS = vsc;
			} else {
				System.out.println("  (" + versionString(v)
					+ ": idem)");
			}
		}
		System.out.println("----------------------");
		if (certID.size() == 0) {
			System.out.println("No server certificate !");
		} else {
			System.out.println("Server certificate(s):");
			for (String cc : certID) {
				System.out.println("  " + cc);
			}
		}
		System.out.println("----------------------");
		int agMaxStrength = Constants.STRONG;
		int agMinStrength = Constants.STRONG;
		boolean vulnBEAST = false;
		for (int v : sv) {
			Set<Integer> vsc = suppCS.get(v);
			agMaxStrength = Math.min(
				maxStrength(vsc), agMaxStrength);
			agMinStrength = Math.min(
				minStrength(vsc), agMinStrength);
			if (!vulnBEAST) {
				vulnBEAST = testBEAST(isa, v, vsc,proxy);
			}
		}
		System.out.println("Minimal encryption strength:     "
			+ strengthString(agMinStrength));
		System.out.println("Achievable encryption strength:  "
			+ strengthString(agMaxStrength));
		System.out.println("BEAST status: "
			+ (vulnBEAST ? "vulnerable" : "protected"));
		System.out.println("CRIME status: "
			+ (compress ? "vulnerable" : "protected"));
		
	}
	
	private static final void makeCS(int suite, String name,
			boolean isCBC, int strength)
		{
			CipherSuite cs = new CipherSuite();
			cs.setSuite(suite);
			cs.setName(name);
			cs.setCBC(isCBC);
			cs.setStrength(strength);
			Constants.CIPHER_SUITES.put(suite, cs);

			/*
			 * Consistency test: the strength and CBC status can normally
			 * be inferred from the name itself.
			 */
			boolean inferredCBC = name.contains("_CBC_");
			int inferredStrength;
			if (name.contains("_NULL_")) {
				inferredStrength = Constants.CLEAR;
			} else if (name.contains("DES40") || name.contains("_40_")
				|| name.contains("EXPORT40"))
			{
				inferredStrength = Constants.WEAK;
			} else if ((name.contains("_DES_") || name.contains("DES_64"))
				&& !name.contains("DES_192"))
			{
				inferredStrength = Constants.MEDIUM;
			} else {
				inferredStrength = Constants.STRONG;
			}
			if (inferredStrength != strength || inferredCBC != isCBC) {
				throw new RuntimeException(
					"wrong classification: " + name);
			}
		}

		
		
		static Set<Integer> supportedSuites(InetSocketAddress isa, int version,
				Set<String> serverCertID,Proxy proxy)
			{
				Set<Integer> cs = new TreeSet<Integer>(Constants.CIPHER_SUITES.keySet());
				Set<Integer> rs = new TreeSet<Integer>();
				for (;;) {
					ServerHello sh = connect(isa, version, cs,proxy);
					if (sh == null) {
						break;
					}
					if (!cs.contains(sh.getCipherSuite())) {
						System.err.printf("[ERR: server wants to use"
							+ " cipher suite 0x%04X which client"
							+ " did not announce]", sh.getCipherSuite());
						System.err.println();
						break;
					}
					cs.remove(sh.getCipherSuite());
					rs.add(sh.getCipherSuite());
					if (sh.getServerCertName() != null) {
						serverCertID.add(sh.getServerCertHash()
							+ ": " + sh.getServerCertHash());
					}
				}
				return rs;
			}
		static ServerHello connect(InetSocketAddress isa,
				int version, Collection<Integer> cipherSuites) {
			return connect(isa,version,cipherSuites,null);
		}
		/*
		 * Connect to the server, send a ClientHello, and decode the
		 * response (ServerHello). On error, null is returned.
		 */
		static ServerHello connect(InetSocketAddress isa,
			int version, Collection<Integer> cipherSuites,Proxy proxy)
		{
			Socket s = null;
			try {
//				SocketAddress proxyAddr = new InetSocketAddress("127.0.0.1", 9150);
//		        Proxy pr = new Proxy(Proxy.Type.SOCKS,proxyAddr);
				if(proxy!=null) {
					s = new Socket(proxy);
				}else {
					s = new Socket();
				}
				try {
					s.connect(isa);
					
				} catch (IOException ioe) {
					System.err.println("could not connect to "
						+ isa + ": " + ioe.toString());
					return null;
				}
				byte[] ch = makeClientHello(version, cipherSuites);
				OutputRecord orec = new OutputRecord(
					s.getOutputStream());
				orec.setType(Constants.HANDSHAKE);
				orec.setVersion(version);
				orec.write(ch);
				orec.flush();
				return new ServerHello(s.getInputStream());
			} catch (IOException ioe) {
				// ignored
			} finally {
				try {
					s.close();
				} catch (IOException ioe) {
					// ignored
				}
			}
			return null;
		}
		static ServerHelloSSLv2 connectV2(InetSocketAddress isa) {
			return connectV2(isa,null);
		}
		/*
		 * Connect to the server, send a SSLv2 CLIENT HELLO, and decode
		 * the response (SERVER HELLO). On error, null is returned.
		 */
		static ServerHelloSSLv2 connectV2(InetSocketAddress isa,Proxy proxy)
		
		{
			Socket s = null;
			try {
				if(proxy!=null) {
					s = new Socket(proxy);
				}else {
					s = new Socket();
				}			
				try {
					s.connect(isa);
				} catch (IOException ioe) {
					System.err.println("could not connect to "
						+ isa + ": " + ioe.toString());
					return null;
				}
				s.getOutputStream().write(Constants.SSL2_CLIENT_HELLO);
				return new ServerHelloSSLv2(s.getInputStream());
			} catch (IOException ioe) {
				// ignored
			} finally {
				try {
					s.close();
				} catch (IOException ioe) {
					// ignored
				}
			}
			return null;
		}
		
		static String versionString(int version)
		{
			if (version == 0x0200) {
				return "SSLv2";
			} else if (version == 0x0300) {
				return "SSLv3";
			} else if ((version >>> 8) == 0x03) {
				return "TLSv1." + ((version & 0xFF) - 1);
			} else {
				return String.format("UNKNOWN_VERSION:0x%04X", version);
			}
		}
		
		static final String cipherSuiteStringV2(int suite)
		{
			CipherSuite cs = Constants.CIPHER_SUITES.get(suite);
			if (cs == null) {
				return String.format("UNKNOWN_SUITE:%02X,%02X,%02X",
					suite >> 16, (suite >> 8) & 0xFF, suite & 0XFF);
			} else {
				return cs.getName();
			}
		}
		
		static byte[] makeClientHello(int version,
				Collection<Integer> cipherSuites)
			{
				try {
					return makeClientHello0(version, cipherSuites);
				} catch (IOException ioe) {
					throw new RuntimeException(ioe);
				}
			}

			static byte[] makeClientHello0(int version,
				Collection<Integer> cipherSuites)
				throws IOException
			{
				ByteArrayOutputStream b = new ByteArrayOutputStream();

				/*
				 * Message header:
				 *   message type: one byte (1 = "ClientHello")
				 *   message length: three bytes (this will be adjusted
				 *   at the end of this method).
				 */
				b.write(1);
				b.write(0);
				b.write(0);
				b.write(0);

				/*
				 * The maximum version that we intend to support.
				 */
				b.write(version >>> 8);
				b.write(version);

				/*
				 * The client random has length 32 bytes, but begins with
				 * the client's notion of the current time, over 32 bits
				 * (seconds since 1970/01/01 00:00:00 UTC, not counting
				 * leap seconds).
				 */
				byte[] rand = new byte[32];
				RNG.nextBytes(rand);
				Encryption.enc32be((int)(System.currentTimeMillis() / 1000), rand, 0);
				b.write(rand);

				/*
				 * We send an empty session ID.
				 */
				b.write(0);

				/*
				 * The list of cipher suites (list of 16-bit values; the
				 * list length in bytes is written first).
				 */
				int num = cipherSuites.size();
				byte[] cs = new byte[2 + num * 2];
				Encryption.enc16be(num * 2, cs, 0);
				int j = 2;
				for (int s : cipherSuites) {
					Encryption.enc16be(s, cs, j);
					j += 2;
				}
				b.write(cs);

				/*
				 * Compression methods: we claim to support Deflate (1)
				 * and the standard no-compression (0), with Deflate
				 * being preferred.
				 */
				b.write(2);
				b.write(1);
				b.write(0);

				/*
				 * If we had extensions to add, they would go here.
				 */

				/*
				 * We now get the message as a blob. The message length
				 * must be adjusted in the header.
				 */
				byte[] msg = b.toByteArray();
				Encryption.enc24be(msg.length - 4, msg, 1);
				return msg;
			}
			static final String cipherSuiteString(int suite)
			{
				CipherSuite cs = Constants.CIPHER_SUITES.get(suite);
				if (cs == null) {
					return String.format("UNKNOWN_SUITE:0x%04X", cs);
				} else {
					return cs.getName();
				}
			}
			
			static int minStrength(Set<Integer> supp)
			{
				int m = Constants.STRONG;
				for (int suite : supp) {
					CipherSuite cs = Constants.CIPHER_SUITES.get(suite);
					if (cs == null) {
						continue;
					}
					if (cs.getStrength() < m) {
						m = cs.getStrength();
					}
				}
				return m;
			}

			static int maxStrength(Set<Integer> supp)
			{
				int m = Constants.CLEAR;
				for (int suite : supp) {
					CipherSuite cs = Constants.CIPHER_SUITES.get(suite);
					if (cs == null) {
						continue;
					}
					if (cs.getStrength() > m) {
						m = cs.getStrength();
					}
				}
				return m;
			}

			static boolean testBEAST(InetSocketAddress isa,
				int version, Set<Integer> supp,Proxy proxy)
			{
				/*
				 * TLS 1.1+ is not vulnerable to BEAST.
				 * We do not test SSLv2 either.
				 */
				if (version < 0x0300 || version > 0x0301) {
					return false;
				}

				/*
				 * BEAST attack works if the server allows the client to
				 * use a CBC cipher. Existing clients also supports RC4,
				 * so we consider that a server protects the clients if
				 * it chooses RC4 over CBC streams when given the choice.
				 * We only consider strong cipher suites here.
				 */
				List<Integer> strongCBC = new ArrayList<Integer>();
				List<Integer> strongStream = new ArrayList<Integer>();
				for (int suite : supp) {
					CipherSuite cs = Constants.CIPHER_SUITES.get(suite);
					if (cs == null) {
						continue;
					}
					if (cs.getStrength() < Constants.STRONG) {
						continue;
					}
					if (cs.isCBC()) {
						strongCBC.add(suite);
					} else {
						strongStream.add(suite);
					}
				}
				if (strongCBC.size() == 0) {
					return false;
				}
				if (strongStream.size() == 0) {
					return true;
				}
				List<Integer> ns = new ArrayList<Integer>(strongCBC);
				ns.addAll(strongStream);
				ServerHello sh = connect(isa, version, ns,proxy);
				return !strongStream.contains(sh.getCipherSuite());
			}
			
			static final String strengthString(int strength)
			{
				switch (strength) {
				case Constants.CLEAR:  return "no encryption";
				case Constants.WEAK:   return "weak encryption (40-bit)";
				case Constants.MEDIUM: return "medium encryption (56-bit)";
				case Constants.STRONG: return "strong encryption (96-bit or more)";
				default:
					throw new Error("strange strength: " + strength);
				}
			}
}
