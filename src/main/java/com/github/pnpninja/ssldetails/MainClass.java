package com.github.pnpninja.ssldetails;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.SocketAddress;
import java.util.List;

public class MainClass {

	public static void main(String[] args) {
		//System.out.println(Constants.CIPHER_SUITES.toString());
		SocketAddress proxyAddr = new InetSocketAddress("userproxy.visa.com",443);
		Proxy pr = new Proxy(Proxy.Type.HTTP,proxyAddr);
		SSLDetails.printSSLDetails("google.com", 443,pr);
		List<CipherSuite> cs = SSLDetails.getCipherSuites("google.com", 443,pr);
		System.out.println(cs.size());

	}

}
