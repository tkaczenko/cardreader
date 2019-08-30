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
 * $Id: IrisBiometricSubtypeInfo.java 1799 2018-10-30 16:25:48Z martijno $
 */

package org.jmrtd.lds.iso19794;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

import org.jmrtd.lds.AbstractListInfo;

/**
 * Iris biometric subtype data block (containing iris image data blocks)
 * based on Section 6.5.3 and Table 3 of
 * ISO/IEC 19794-6 2005.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1799 $
 */
public class IrisBiometricSubtypeInfo extends AbstractListInfo<IrisImageInfo> {

  private static final long serialVersionUID = -6588640634764878039L;

  /** Biometric subtype value. */
  public static final int EYE_UNDEF = 0;

  /** Biometric subtype value. */
  public static final int EYE_RIGHT = 1;

  /** Biometric subtype value. */
  public static final int EYE_LEFT = 2;

  private int imageFormat;
  private int biometricSubtype;

  /**
   * Constructs a biometric subtype info.
   *
   * @param biometricSubtype one of {@link #EYE_UNDEF}, {@link #EYE_RIGHT}, {@link #EYE_LEFT}
   * @param imageFormat the image format as specified in the {@link IrisInfo} of which this is a part
   * @param irisImageInfos the iris image info records
   */
  public IrisBiometricSubtypeInfo(int biometricSubtype, int imageFormat, List<IrisImageInfo> irisImageInfos) {
    this.biometricSubtype = biometricSubtype;
    this.imageFormat = imageFormat;
    addAll(irisImageInfos);
  }

  /**
   * Constructs an iris biometric subtype from binary encoding.
   *
   * @param in an input stream
   * @param imageFormat the image format used
   *
   * @throws IOException if reading fails
   */
  public IrisBiometricSubtypeInfo(InputStream in, int imageFormat) throws IOException {
    this.imageFormat = imageFormat;
    readObject(in);
  }

  /**
   * Reads an iris biometric subtype from input stream.
   *
   * @param inputStream an input stream
   *
   * @throws IOException if reading fails
   */
  @Override
  public void readObject(InputStream inputStream) throws IOException {
    DataInputStream dataIn = inputStream instanceof DataInputStream ? (DataInputStream)inputStream : new DataInputStream(inputStream);

    /* Iris biometric subtype header */
    this.biometricSubtype = dataIn.readUnsignedByte();      /* 1 */
    int count = dataIn.readUnsignedShort();                 /* + 2 = 3 */

    long constructedDataLength = 0L;

    for (int i = 0; i < count; i++) {
      IrisImageInfo imageInfo = new IrisImageInfo(inputStream, imageFormat);
      constructedDataLength += imageInfo.getRecordLength();
      add(imageInfo);
    }
    //		if (dataLength != constructedDataLength) {
    //			throw new IllegalStateException("dataLength = " + dataLength + ", constructedDataLength = " + constructedDataLength);
    //		}
  }

  /**
   * Writes an iris biometric subtype to output stream.
   *
   * @param outputStream an output stream
   *
   * @throws IOException if writing fails
   */
  @Override
  public void writeObject(OutputStream outputStream) throws IOException {
    DataOutputStream dataOut = outputStream instanceof DataOutputStream ? (DataOutputStream)outputStream : new DataOutputStream(outputStream);

    dataOut.writeByte(biometricSubtype & 0xFF);					/* 1 */

    List<IrisImageInfo> irisImageInfos = getSubRecords();
    dataOut.writeShort(irisImageInfos.size() & 0xFFFF);			/* + 2 = 3 */
    for (IrisImageInfo irisImageInfo: irisImageInfos) {
      irisImageInfo.writeObject(dataOut);
    }
  }

  /**
   * Returns the record length.
   *
   * @return the record length
   */
  public long getRecordLength() {
    long result = 3;
    List<IrisImageInfo> irisImageInfos = getSubRecords();
    for (IrisImageInfo irisImageInfo: irisImageInfos) {
      result += irisImageInfo.getRecordLength();
    }
    return result;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + biometricSubtype;
    result = prime * result + imageFormat;
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!super.equals(obj)) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }

    IrisBiometricSubtypeInfo other = (IrisBiometricSubtypeInfo) obj;
    return biometricSubtype == other.biometricSubtype
        && imageFormat == other.imageFormat;
  }

  @Override
  public String toString() {
    List<IrisImageInfo> irisImageInfos = getSubRecords();
    return "IrisBiometricSubtypeInfo ["
    + "biometric subtype: " + biometricSubtypeToString(biometricSubtype)
    + ", imageCount = " + irisImageInfos.size()
    + "]";
  }

  /**
   * The biometric subtype (feature identifier).
   * Result is one of {@link #EYE_UNDEF}, {@link #EYE_RIGHT}, {@link #EYE_LEFT}.
   *
   * @return the biometric subtype.
   */
  public int getBiometricSubtype() {
    return biometricSubtype;
  }

  /**
   * Returns the image format used in the images encoded in this record.
   *
   * @return the image format
   */
  public int getImageFormat() {
    return imageFormat;
  }

  /**
   * Returns the iris image infos embedded in this iris biometric subtype info.
   *
   * @return the embedded iris image infos
   */
  public List<IrisImageInfo> getIrisImageInfos() {
    return getSubRecords();
  }

  /**
   * Adds an iris image info to this iris biometric subtype info.
   *
   * @param irisImageInfo the iris image info to add
   */
  public void addIrisImageInfo(IrisImageInfo irisImageInfo) {
    add(irisImageInfo);
  }

  /**
   * Removes an iris image info from this iris biometric subtype info.
   *
   * @param index the index of the iris image info to remove
   */
  public void removeIrisImageInfo(int index) {
    remove(index);
  }

  /* ONLY PRIVATE METHODS BELOW */

  /**
   * Returns a textual representation of the given biometric sub-type code.
   *
   * @param biometricSubtype the biometric sub-type code
   *
   * @return a human readable string such as {@code "Left eye"}, {@code "Right eye"}, or {@code "Undefined"}
   */
  private static String biometricSubtypeToString(int biometricSubtype) {
    switch (biometricSubtype) {
      case EYE_LEFT:
        return "Left eye";
      case EYE_RIGHT:
        return "Right eye";
      case EYE_UNDEF:
        return "Undefined";
      default:
        throw new NumberFormatException("Unknown biometric subtype: " + Integer.toHexString(biometricSubtype));
    }
  }
}
