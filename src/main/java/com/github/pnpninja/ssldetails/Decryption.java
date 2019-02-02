package com.github.pnpninja.ssldetails;

public final class Decryption {
	
	static final int dec16be(byte[] buf, int off)
	{
		return ((buf[off] & 0xFF) << 8)
			| (buf[off + 1] & 0xFF);
	}

	static final int dec24be(byte[] buf, int off)
	{
		return ((buf[off] & 0xFF) << 16)
			| ((buf[off + 1] & 0xFF) << 8)
			| (buf[off + 2] & 0xFF);
	}

	static final int dec32be(byte[] buf, int off)
	{
		return ((buf[off] & 0xFF) << 24)
			| ((buf[off + 1] & 0xFF) << 16)
			| ((buf[off + 2] & 0xFF) << 8)
			| (buf[off + 3] & 0xFF);
	}

}
