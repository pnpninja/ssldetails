package com.github.pnpninja.ssldetails;

final class CipherSuite {

	private int suite;
	private String name;
	private boolean isCBC;
	private int strength;
	public int getSuite() {
		return suite;
	}
	public void setSuite(int suite) {
		this.suite = suite;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public boolean isCBC() {
		return isCBC;
	}
	public void setCBC(boolean isCBC) {
		this.isCBC = isCBC;
	}
	public int getStrength() {
		return strength;
	}
	public void setStrength(int strength) {
		this.strength = strength;
	}
	
	
}
