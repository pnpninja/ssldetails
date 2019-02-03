package com.github.pnpninja.ssldetails;

public class MainClass {

	public static void main(String[] args) {
		System.out.println(Constants.CIPHER_SUITES.toString());
		SSLDetails.printSSLDetails("google.com", 443);

	}

}
