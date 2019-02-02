package com.github.pnpninja.ssldetails;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

public class Reader {

	static void readFully(InputStream in, byte[] buf)
			throws IOException
		{
			readFully(in, buf, 0, buf.length);
		}

		static void readFully(InputStream in, byte[] buf, int off, int len)
			throws IOException
		{
			while (len > 0) {
				int rlen = in.read(buf, off, len);
				if (rlen < 0) {
					throw new EOFException();
				}
				off += rlen;
				len -= rlen;
			}
		}
}
