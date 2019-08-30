/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2018  The JMRTD team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * $Id: PositionInputStream.java 1817 2019-08-02 12:09:17Z martijno $
 */

package org.jmrtd.io;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Logger;

/**
 * A stream that decorates an existing stream and keeps track of the current position.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1817 $
 */
public class PositionInputStream extends InputStream {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private static final long MARK_NOT_SET = -1L;

  private InputStream carrier;

  private long position;
  private long markedPosition;

  /**
   * Constructs a position input stream by decorating an existing input stream.
   *
   * @param carrier the existing input stream
   */
  public PositionInputStream(InputStream carrier) {
    this.carrier = carrier;
    position = 0L;
    markedPosition = MARK_NOT_SET;
  }

  @Override
  public int read() throws IOException {
    int b = carrier.read();
    if (b >= 0) {
      position++;
    }
    return b;
  }

  @Override
  public int read(byte[] dest) throws IOException {
    return read(dest, 0, dest.length);
  }

  @Override
  public int read(byte[] dest, int offset, int length) throws IOException {
    int bytesRead = carrier.read(dest, offset, length);
    position += bytesRead;
    return bytesRead;
  }

  @Override
  public long skip(long n) throws IOException {
    long skippedBytes = carrier.skip(n);
    if (skippedBytes <= 0) {
      LOGGER.warning("Carrier (" + carrier.getClass().getCanonicalName() + ")'s skip(" + n + ") only skipped " + skippedBytes + ", position = " + position);
    }

    position += skippedBytes;
    return skippedBytes;
  }

  @Override
  public synchronized void mark(int readLimit) {
    carrier.mark(readLimit);
    markedPosition = position;
  }

  @Override
  public synchronized void reset() throws IOException {
    carrier.reset();
    position = markedPosition;
  }

  @Override
  public boolean markSupported() {
    return carrier.markSupported();
  }

  /**
   * Returns the position within the input stream.
   *
   * @return the position within the input stream
   */
  public long getPosition() {
    return position;
  }
}
