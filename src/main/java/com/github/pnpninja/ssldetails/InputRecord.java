package com.github.pnpninja.ssldetails;

import java.io.IOException;
import java.io.InputStream;

final class InputRecord extends InputStream {

	private InputStream in;
	private byte[] buffer = new byte[Constants.MAX_RECORD_LEN + 5];
	private int ptr, end;
	private int version;
	private int type;
	private int expectedType;

	InputRecord(InputStream in)
	{
		this.in = in;
		ptr = 0;
		end = 0;
	}

	void setExpectedType(int expectedType)
	{
		this.expectedType = expectedType;
	}

	int getVersion()
	{
		return version;
	}

	private void refill()
		throws IOException
	{
		for (;;) {
			Reader.readFully(in, buffer, 0, 5);
			type = buffer[0] & 0xFF;
			version = Decryption.dec16be(buffer, 1);
			end = Decryption.dec16be(buffer, 3);
			Reader.readFully(in, buffer, 0, end);
			ptr = 0;
			if (type != expectedType) {
				if (type == Constants.ALERT) {
					/*
					 * We just ignore alert
					 * messages.
					 */
					continue;
				}
				throw new IOException(
					"unexpected record type: "
					+ type);
			}
			return;
		}
	}

	public int read()
		throws IOException
	{
		while (ptr == end) {
			refill();
		}
		return buffer[ptr ++] & 0xFF;
	}

	public int read(byte[] buf, int off, int len)
		throws IOException
	{
		while (ptr == end) {
			refill();
		}
		int clen = Math.min(end - ptr, len);
		System.arraycopy(buffer, ptr, buf, off, clen);
		ptr += clen;
		return clen;
	}
}
