package com.github.pnpninja.ssldetails;

public final class Encryption {

	static final void enc16be(int val, byte[] buf, int off)
	{
		buf[off] = (byte)(val >>> 8);
		buf[off + 1] = (byte)val;
	}

	static final void enc24be(int val, byte[] buf, int off)
	{
		buf[off] = (byte)(val >>> 16);
		buf[off + 1] = (byte)(val >>> 8);
		buf[off + 2] = (byte)val;
	}

	static final void enc32be(int val, byte[] buf, int off)
	{
		buf[off] = (byte)(val >>> 24);
		buf[off + 1] = (byte)(val >>> 16);
		buf[off + 2] = (byte)(val >>> 8);
		buf[off + 3] = (byte)val;
	}
}
