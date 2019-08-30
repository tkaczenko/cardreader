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
 * $Id: AbstractTaggedLDSFile.java 1811 2019-05-27 14:08:20Z martijno $
 */

package org.jmrtd.lds;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVOutputStream;

/**
 * Base class for TLV based LDS files.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1811 $
 */
public abstract class AbstractTaggedLDSFile extends AbstractLDSFile {

  private static final long serialVersionUID = -4761360877353069639L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private int tag;
  private int length;

  /**
   * Constructs a data group. This constructor
   * is only visible to the other classes in this package.
   *
   * @param dataGroupTag data group tag
   */
  protected AbstractTaggedLDSFile(int dataGroupTag) {
    this.tag = dataGroupTag;
  }

  /**
   * Constructs a data group from the DER encoded data in the
   * given input stream.
   *
   * @param tag the tag
   * @param inputStream an input stream
   *
   * @throws IOException on error reading input stream
   */
  protected AbstractTaggedLDSFile(int tag, InputStream inputStream) throws IOException {
    this.tag = tag;
    readObject(inputStream);
  }

  /**
   * Reads the contents of this LDS file, including tag and length from an input stream.
   *
   * @param inputStream the stream to read from
   *
   * @throws IOException if reading from the stream fails
   */
  @Override
  protected void readObject(InputStream inputStream) throws IOException {
    TLVInputStream tlvIn = inputStream instanceof TLVInputStream ? (TLVInputStream)inputStream : new TLVInputStream(inputStream);
    int inputTag = tlvIn.readTag();
    if (inputTag != tag) {
      throw new IllegalArgumentException("Was expecting tag " + Integer.toHexString(tag) + ", found " + Integer.toHexString(inputTag));
    }
    length = tlvIn.readLength();
    readContent(tlvIn);
//    readContent(new SplittableInputStream(inputStream, length)); // was using this in <= 0.7.9 -- MO
  }

  @Override
  protected void writeObject(OutputStream outputStream) throws IOException {
    TLVOutputStream tlvOut = outputStream instanceof TLVOutputStream ? (TLVOutputStream)outputStream : new TLVOutputStream(outputStream);
    int ourTag = getTag();
    if (tag != ourTag) {
      tag = ourTag;
    }
    tlvOut.writeTag(ourTag);
    byte[] value = getContent();
    int ourLength = value == null ? 0 : value.length;
    if (length != ourLength) {
      length = ourLength;
    }
    tlvOut.writeValue(value);
  }

  /**
   * Reads the contents of the data group from an input stream.
   * Client code implementing this method should only read the contents
   * from the input stream, not the tag or length of the data group.
   *
   * @param inputStream the input stream to read from
   *
   * @throws IOException on error reading from input stream
   */
  protected abstract void readContent(InputStream inputStream) throws IOException;

  /**
   * Writes the contents of the data group to an output stream.
   * Client code implementing this method should only write the contents
   * to the output stream, not the tag or length of the data group.
   *
   * @param outputStream the output stream to write to
   *
   * @throws IOException on error writing to output stream
   */
  protected abstract void writeContent(OutputStream outputStream) throws IOException;

  /**
   * Returns a textual representation of this file.
   *
   * @return a textual representation of this file
   */
  @Override
  public String toString() {
    return "TaggedLDSFile [" + Integer.toHexString(getTag()) + " (" + getLength() + ")]";
  }

  /**
   * Returns the tag that identifies this LDS file.
   *
   * @return the tag of this LDS file
   */
  public int getTag() {
    return tag;
  }

  /**
   * The length of the value of the data group.
   *
   * @return the length of the value of the data group
   */
  public int getLength() {
    if (length <= 0) {
      length = getContent().length;
    }
    return length;
  }

  /**
   * Returns the value part of this LDS file.
   *
   * @return the value as byte array
   */
  private byte[] getContent() {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    try {
      writeContent(outputStream);
      outputStream.flush();
      return outputStream.toByteArray();
    } catch (IOException ioe) {
      throw new IllegalStateException("Could not get DG content", ioe);
    } finally {
      try {
        outputStream.close();
      } catch (IOException ioe) {
        LOGGER.log(Level.FINE, "Error closing stream", ioe);
      }
    }
  }
}
