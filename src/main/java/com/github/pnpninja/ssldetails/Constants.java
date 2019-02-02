package com.github.pnpninja.ssldetails;

final class Constants {
	
	static final int CLEAR  = 0; // no encryption
	static final int WEAK   = 1; // weak encryption: 40-bit key
	static final int MEDIUM = 2; // medium encryption: 56-bit key
	static final int STRONG = 3; // strong encryption
	
	static final String strengthString(int strength)
	{
		switch (strength) {
		case CLEAR:  return "no encryption";
		case WEAK:   return "weak encryption (40-bit)";
		case MEDIUM: return "medium encryption (56-bit)";
		case STRONG: return "strong encryption (96-bit or more)";
		default:
			throw new Error("strange strength: " + strength);
		}
	}
	
	static final int CHANGE_CIPHER_SPEC = 20;
	static final int ALERT              = 21;
	static final int HANDSHAKE          = 22;
	static final int APPLICATION        = 23;
	static final int MAX_RECORD_LEN = 16384;

}
