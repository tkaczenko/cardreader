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
 * $Id: AbstractImageInfo.java 1808 2019-03-07 21:32:19Z martijno $
 */

package org.jmrtd.lds;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.io.SplittableInputStream;

/**
 * Base class for image infos.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1808 $
 */
public abstract class AbstractImageInfo implements ImageInfo {

  private static final long serialVersionUID = 2870092217269116309L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private int type;
  private String mimeType;
  private byte[] imageBytes;

  // FIXME: It's not clear how serialization should work if not fully read. (Clients should only serialize if imageBytes != null.)
  private transient SplittableInputStream splittableInputStream;
  private int imagePositionInInputStream;
  private int imageLength;

  private int width;
  private int height;

  /* PACKAGE ONLY VISIBLE CONSTRUCTORS BELOW */

  /**
   * Constructs a default abstract image info.
   */
  AbstractImageInfo() {
    this(TYPE_UNKNOWN, 0, 0, null);
  }

  /**
   * Constructs an abstract image info with a type.
   *
   * @param type the type of image
   */
  protected AbstractImageInfo(int type) {
    this (type, 0, 0, null);
  }

  /**
   * Constructs an abstract image info with a type and a mime-type.
   *
   * @param type the type
   * @param mimeType the mime-type string
   */
  protected AbstractImageInfo(int type, String mimeType) {
    this(type, 0, 0, mimeType);
  }

  /**
   * Constructs an abstract image info with full parameters.
   *
   * @param type the type of image
   * @param width the width
   * @param height the height
   * @param mimeType the mime-type string
   */
  private AbstractImageInfo(int type, int width, int height, String mimeType) {
    this.type = type;
    this.mimeType = mimeType;
    this.width = width;
    this.height = height;
  }

  /* PUBLIC CONSRTUCTOR BELOW */

  /**
   * Constructs an abstract image info.
   *
   * @param type type of image info
   * @param width width of image
   * @param height height of image
   * @param inputStream encoded image
   * @param imageLength length of encoded image
   * @param mimeType mime-type of encoded image
   *
   * @throws IOException if reading fails
   */
  public AbstractImageInfo(int type, int width, int height, InputStream inputStream, long imageLength, String mimeType) throws IOException {
    this(type, width, height, mimeType);
    readImage(inputStream, imageLength);
  }

  /* PUBLIC METHODS BELOW */

  /**
   * Returns the content-type,
   * where content-type is one of
   * {@link ImageInfo#TYPE_PORTRAIT},
   * {@link ImageInfo#TYPE_FINGER},
   * {@link ImageInfo#TYPE_IRIS},
   * {@link ImageInfo#TYPE_SIGNATURE_OR_MARK}.
   *
   * @return content type
   */
  public int getType() {
    return type;
  }

  /**
   * Returns the mime-type of the encoded image.
   *
   * @return the mime-type of the encoded image
   */
  public String getMimeType() {
    return mimeType;
  }

  /**
   * Returns the width of the image.
   *
   * @return the width of the image
   */
  public int getWidth() {
    return width;
  }

  /**
   * Returns the height of the image.
   *
   * @return the height of the image
   */
  public int getHeight() {
    return height;
  }

  /**
   * Returns the length of the encoded image.
   *
   * @return the length of the encoded image
   */
  public int getImageLength() {
    /* DEBUG: START */
    if (splittableInputStream != null) {
      return imageLength;
    }
    /* DEBUG: END */

    if (imageBytes == null) {
      throw new IllegalStateException("Cannot get length of null");
    }

    return imageBytes.length;
  }

  /**
   * Returns a textual representation of this image info.
   *
   * @return a textual representation of this image info
   */
  @Override
  public String toString() {
    return new StringBuilder()
        .append(this.getClass().getSimpleName())
        .append(" [")
        .append("type: ").append(typeToString(type) + ", ")
        .append("size: ").append(getImageLength())
        .append("]")
        .toString();
  }

  @Override
  public int hashCode() {
    int result = 1234567891;
    result = 3 * result + 5 * type;
    result += 5 * (mimeType == null ? 1337 : mimeType.hashCode()) + 7;
    result += 7 * getImageLength() + 11;
    return result;
  }

  @Override
  public boolean equals(Object other) {
    try {
      if (other == null) {
        return false;
      }
      if (other == this) {
        return true;
      }
      if (!other.getClass().equals(this.getClass())) {
        return false;
      }

      AbstractImageInfo otherImageInfo = (AbstractImageInfo)other;
      return (Arrays.equals(getImageBytes(), otherImageInfo.getImageBytes()))
          // && getImageLength() == otherImageInfo.getImageLength()
          && (mimeType == null && otherImageInfo.mimeType == null || mimeType != null && mimeType.equals(otherImageInfo.mimeType))
          && type == otherImageInfo.type;
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception" + e);
      return false;
    }
  }

  /**
   * Encodes this image info.
   *
   * @return a byte array containing the encoded image info
   */
  public byte[] getEncoded() {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try {
      writeObject(out);
    } catch (IOException ioe) {
      LOGGER.log(Level.WARNING, "Exception", ioe);
      return null;
    }
    return out.toByteArray();
  }

  /**
   * Returns the encoded image as an input stream.
   *
   * @return an input stream containing the encoded image
   */
  public InputStream getImageInputStream() {
    /* DEBUG: START */
    if (splittableInputStream != null) {
      return splittableInputStream.getInputStream(imagePositionInInputStream);
      /* DEBUG: END */
    } else if (imageBytes != null) {
      return new ByteArrayInputStream(imageBytes);
    } else {
      throw new IllegalStateException("Both the byte buffer and the stream are null");
    }
  }

  /**
   * Clients should call this method after positioning the input stream to the
   * image bytes.
   *
   * @param inputStream input stream
   * @param imageLength image length
   *
   * @throws IOException on error reading the input stream, for example at EOF
   */
  protected void readImage(InputStream inputStream, long imageLength) throws IOException {
    /* DEBUG: START */
    //    if (inputStream instanceof SplittableInputStream) {
    //      this.imageBytes = null;
    //      this.splittableInputStream = (SplittableInputStream)inputStream;
    //      this.imagePositionInInputStream = splittableInputStream.getPosition();
    //
    //      this.imageLength = (int)imageLength;
    //      long totalSkippedBytes = 0;
    //      while (totalSkippedBytes < imageLength) {
    //        long currentlySkippedBytes = splittableInputStream.skip(imageLength - totalSkippedBytes);
    //        totalSkippedBytes += currentlySkippedBytes;
    //      }
    //    } else {
    /* DEBUG: END */
    this.splittableInputStream = null;
    this.imageBytes = new byte[(int)imageLength];
    DataInputStream dataIn = new DataInputStream(inputStream);
    dataIn.readFully(this.imageBytes);
    //    }
  }

  /**
   * Writes this image to a stream.
   *
   * @param outputStream the stream to write to
   *
   * @throws IOException on error writing to the stream
   */
  protected void writeImage(OutputStream outputStream) throws IOException {
    outputStream.write(getImageBytes());
  }

  /**
   * Sets the mime-type.
   *
   * @param mimeType the new mime-type
   */
  protected final void setMimeType(String mimeType) {
    this.mimeType = mimeType;
  }

  /**
   * Sets the type.
   *
   * @param type the new type
   */
  protected final void setType(int type) {
    this.type = type;
  }

  /**
   * Sets the width of this image.
   *
   * @param width the new width
   */
  protected final void setWidth(int width) {
    this.width = width;
  }

  /**
   * Sets the height of this image.
   *
   * @param height the new height
   */
  protected final void setHeight(int height) {
    this.height = height;
  }

  /**
   * Sets the encoded image bytes of this image.
   *
   * @param imageBytes the image bytes
   */
  protected final void setImageBytes(byte[] imageBytes) {
    if (imageBytes == null) {
      throw new IllegalArgumentException("Cannot set null image bytes");
    }

    try {
      readImage(new ByteArrayInputStream(imageBytes), imageBytes.length);
    } catch (IOException e) {
      LOGGER.log(Level.WARNING, "Exception", e);
    }
  }

  /**
   * Reads this object from a stream.
   *
   * @param inputStream the stream to read from
   *
   * @throws IOException on error reading from the stream
   */
  protected abstract void readObject(InputStream inputStream) throws IOException;

  /**
   * Writes this object to a stream.
   *
   * @param outputStream the stream to write to
   *
   * @throws IOException on error writing to the stream
   */
  protected abstract void writeObject(OutputStream outputStream) throws IOException;

  /* ONLY PRIVATE METHODS BELOW */

  /**
   * Reads the image bytes from the stream.
   *
   * @return the image bytes
   *
   * @throws IOException on error reading from the stream
   */
  private byte[] getImageBytes() throws IOException {
    InputStream inputStream = null;
    int length = getImageLength();
    byte[] imageBytes = new byte[length];
    inputStream = getImageInputStream();
    DataInputStream imageInputStream = new DataInputStream(inputStream);
    imageInputStream.readFully(imageBytes);
    return imageBytes;
  }

  /**
   * Returns a human readable string from the image type.
   *
   * @param type the image type
   *
   * @return a human readable string
   */
  private static String typeToString(int type) {
    switch (type) {
      case TYPE_PORTRAIT:
        return "Portrait";
      case TYPE_SIGNATURE_OR_MARK:
        return "Signature or usual mark";
      case TYPE_FINGER:
        return "Finger";
      case TYPE_IRIS:
        return "Iris";
      case TYPE_UNKNOWN:
        return "Unknown";
      default:
        throw new NumberFormatException("Unknown type: " + Integer.toHexString(type));
    }
  }
}
