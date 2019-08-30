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
 * $Id: FingerInfo.java 1799 2018-10-30 16:25:48Z martijno $
 */

package org.jmrtd.lds.iso19794;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.logging.Logger;

import org.jmrtd.cbeff.BiometricDataBlock;
import org.jmrtd.cbeff.CBEFFInfo;
import org.jmrtd.cbeff.ISO781611;
import org.jmrtd.cbeff.StandardBiometricHeader;
import org.jmrtd.lds.AbstractListInfo;

/**
 * Fingerprint general record header and finger image data blocks
 * based on Section 7 and Table 2 of ISO/IEC FCD 19794-4 aka Annex F.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1799 $
 */
public class FingerInfo extends AbstractListInfo<FingerImageInfo> implements BiometricDataBlock {

  private static final long serialVersionUID = 5808625058034008176L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /** Format identifier 'F', 'I', 'R', 0x00. Specified in ISO/IEC 19794-4 Section 7.1, Table 2.  */
  private static final int FORMAT_IDENTIFIER = 0x46495200;

  /** Version number '0', '1', '0', 0x00. Specified in ISO/IEC 19794-4 Section 7.1, Table 2. */
  private static final int VERSION_NUMBER = 0x30313000;

  /** Format owner identifier of ISO/IEC JTC1/SC37. */
  private static final int FORMAT_OWNER_VALUE = 0x0101;

  /**
   * ISO/IEC JTC1/SC37 uses 0x0007 according to <a href="http://www.ibia.org/cbeff/_bdb.php">IBIA</a>.
   * (ISO FCD 19794-4 specified this as 0x0401).
   */
  private static final int FORMAT_TYPE_VALUE = 0x0007;

  /** Scale units points per inch. */
  public static final int SCALE_UNITS_PPI = 1;

  /** Scale units points per centimeter. */
  public static final int SCALE_UNITS_PPCM = 2;

  /** Image compression algorithm type as specified in Section 7.1.13 and Table 3 of ISO 19794-4. */
  public static final int COMPRESSION_UNCOMPRESSED_NO_BIT_PACKING = 0;

  /** Image compression algorithm type as specified in Section 7.1.13 and Table 3 of ISO 19794-4. */
  public static final int COMPRESSION_UNCOMPRESSED_BIT_PACKED = 1;

  /** Image compression algorithm type as specified in Section 7.1.13 and Table 3 of ISO 19794-4. */
  public static final int COMPRESSION_WSQ = 2;

  /** Image compression algorithm type as specified in Section 7.1.13 and Table 3 of ISO 19794-4. */
  public static final int COMPRESSION_JPEG = 3;

  /** Image compression algorithm type as specified in Section 7.1.13 and Table 3 of ISO 19794-4. */
  public static final int COMPRESSION_JPEG2000 = 4;

  /** Image compression algorithm type as specified in Section 7.1.13 and Table 3 of ISO 19794-4. */
  public static final int COMPRESSION_PNG = 5;

  private int captureDeviceId;
  private int acquisitionLevel;
  private int scaleUnits;
  private int scanResolutionHorizontal;
  private int scanResolutionVertical;
  private int imageResolutionHorizontal;
  private int imageResolutionVertical;
  private int depth;
  private int compressionAlgorithm;

  private StandardBiometricHeader sbh;

  /**
   * Constructs a finger info record.
   *
   * @param captureDeviceId capture device identifier
   * @param acquisitionLevel acquisition level
   * @param scaleUnits scale units, one of {@link #SCALE_UNITS_PPI}, {@link #SCALE_UNITS_PPCM}
   * @param scanResolutionHorizontal horizontal scan resolution
   * @param scanResolutionVertical vertical scan resolution
   * @param imageResolutionHorizontal horizontal image resolution
   * @param imageResolutionVertical vertical image resolution
   * @param depth image depth
   * @param compressionAlgorithm compression algorithm, see {@link #getCompressionAlgorithm()} for valid values
   * @param fingerImageInfos the image records
   */
  public FingerInfo(int captureDeviceId, int acquisitionLevel, int scaleUnits,
      int scanResolutionHorizontal, int scanResolutionVertical,
      int imageResolutionHorizontal, int imageResolutionVertical,
      int depth, int compressionAlgorithm,
      List<FingerImageInfo> fingerImageInfos) {
    this(null, captureDeviceId, acquisitionLevel, scaleUnits,
        scanResolutionHorizontal, scanResolutionVertical,
        imageResolutionHorizontal, imageResolutionVertical,
        depth, compressionAlgorithm, fingerImageInfos);
  }

  /**
   * Constructs a finger info record.
   *
   * @param sbh standard biometric header to use
   * @param captureDeviceId capture device identifier
   * @param acquisitionLevel acquisition level
   * @param scaleUnits scale units, one of {@link #SCALE_UNITS_PPI}, {@link #SCALE_UNITS_PPCM}
   * @param scanResolutionHorizontal horizontal scan resolution
   * @param scanResolutionVertical vertical scan resolution
   * @param imageResolutionHorizontal horizontal image resolution
   * @param imageResolutionVertical vertical image resolution
   * @param depth image depth
   * @param compressionAlgorithm compression algorithm, see {@link #getCompressionAlgorithm()} for valid values
   * @param fingerImageInfos the image records
   */
  public FingerInfo(StandardBiometricHeader sbh,
      int captureDeviceId, int acquisitionLevel, int scaleUnits,
      int scanResolutionHorizontal, int scanResolutionVertical,
      int imageResolutionHorizontal, int imageResolutionVertical,
      int depth, int compressionAlgorithm,
      List<FingerImageInfo> fingerImageInfos) {
    this.sbh = sbh;
    this.captureDeviceId = captureDeviceId;
    this.acquisitionLevel = acquisitionLevel;
    this.scaleUnits = scaleUnits;
    this.scanResolutionHorizontal = scanResolutionHorizontal;
    this.scanResolutionVertical = scanResolutionVertical;
    this.imageResolutionHorizontal = imageResolutionHorizontal;
    this.imageResolutionVertical = imageResolutionVertical;
    this.depth = depth;
    this.compressionAlgorithm = compressionAlgorithm;
    addAll(fingerImageInfos);
  }

  /**
   * Constructs a finger info record.
   *
   * @param inputStream input stream
   *
   * @throws IOException on I/O error
   */
  public FingerInfo(InputStream inputStream) throws IOException {
    this(null, inputStream);
  }

  /**
   * Constructs a finger info record.
   *
   * @param sbh standard biometric header to use
   * @param inputStream input stream
   *
   * @throws IOException on I/O error
   */
  public FingerInfo(StandardBiometricHeader sbh, InputStream inputStream) throws IOException {
    this.sbh = sbh;
    readObject(inputStream);
  }

  /**
   * Returns the capture device identifier as specified in Section 7.1.4 of ISO 19794-4.
   * Only the low-order 12 bits are significant.
   *
   * @return the capture device identifier
   */
  public int getCaptureDeviceId() {
    return captureDeviceId;
  }

  /**
   * Returns the image acquisition level as specified in Section 7.1.5 and Table 1 of ISO 19794-4.
   * Valid settings are: 10 (125 ppi), 20 (250 ppi), 30 (500 ppi), 31 (500 ppi), 40 (1000 ppi), 41 (1000 ppi).
   *
   * @return image acquisition level
   */
  public int getAcquisitionLevel() {
    return acquisitionLevel;
  }

  /**
   * Returns the units used to describe the scanning and resolution of the image.
   * Either {@code PPI} or {@code PPCM}. As specified in Section 7.1.7 of ISO 19794-4.
   *
   * @return scale units type
   */
  public int getScaleUnits() {
    return scaleUnits;
  }

  /**
   * Returns the rounded scanning resolution used in the horizontal direction.
   * As specified in Section 7.1.8 of ISO 19794-4.
   * Depending on {@link #getScaleUnits()} the result is either in PPI or PPCM.
   *
   * @return the horizontal scanning resolution
   */
  public int getHorizontalScanningResolution() {
    return scanResolutionHorizontal;
  }

  /**
   * Returns the rounded scanning resolution used in the vertical direction.
   * As specified in Section 7.1.9 of ISO 19794-4.
   * Depending on {@link #getScaleUnits()} the result is either in PPI or PPCM.
   *
   * @return the vertical scanning resolution
   */
  public int getVerticalScanningResolution() {
    return scanResolutionVertical;
  }

  /**
   * Returns the rounded image resolution used in the horizontal direction
   * as specified in Section 7.1.10 of ISO 19794-4.
   * Depending on {@link #getScaleUnits()} the result is either in PPI or PPCM.
   *
   * @return the horizontal image resolution
   */
  public int getHorizontalImageResolution() {
    return imageResolutionHorizontal;
  }

  /**
   * Returns the rounded image resolution used in the vertical direction
   * as specified in Section 7.1.11 of ISO 19794-4.
   * Depending on {@link #getScaleUnits()} the result is either in PPI or PPCM.
   *
   * @return the vertical image resolution
   */
  public int getVerticalImageResolution() {
    return imageResolutionVertical;
  }

  /**
   * Returns the pixel depth. As specified in Section 7.1.12 of ISO 19794-4.
   * Valid values are between {@code 0x01} to {@code 0x10}.
   *
   * @return the pixel depth
   */
  public int getDepth() {
    return depth;
  }

  /**
   * Returns the compression algorithm
   * as specified in Section 7.1.13 of ISO 19794-4.
   * One of
   * {@link #COMPRESSION_UNCOMPRESSED_BIT_PACKED},
   * {@link #COMPRESSION_UNCOMPRESSED_NO_BIT_PACKING},
   * {@link #COMPRESSION_JPEG},
   * {@link #COMPRESSION_JPEG2000},
   * {@link #COMPRESSION_PNG},
   * {@link #COMPRESSION_WSQ}.
   *
   * @return a constant representing the used image compression algorithm
   */
  public int getCompressionAlgorithm() {
    return compressionAlgorithm;
  }

  /**
   * Reads a finger info from an input stream.
   *
   * @param inputStream an input stream
   *
   * @throws IOException if reading fails
   */
  @Override
  public void readObject(InputStream inputStream) throws IOException {
    /* General record header (32) according to Table 2 in Section 7.1 of ISO/IEC 19794-4. */

    DataInputStream dataIn = (inputStream instanceof DataInputStream) ? (DataInputStream)inputStream : new DataInputStream(inputStream);

    int fir0 = dataIn.readInt(); /* header (e.g. "FIR", 0x00) (4) */
    if (fir0 != FORMAT_IDENTIFIER) {
      throw new IllegalArgumentException("'FIR' marker expected! Found " + Integer.toHexString(fir0));
    }

    int version = dataIn.readInt(); /* version in ASCII (e.g. "010" 0x00) (4) */
    if (version != VERSION_NUMBER) {
      throw new IllegalArgumentException("'010' version number expected! Found " + Integer.toHexString(version));
    }

    long recordLength = readUnsignedLong(dataIn, 6); // & 0xFFFFFFFFFFFFL;
    captureDeviceId = dataIn.readUnsignedShort(); /* all zeros means 'unreported', only lower 12-bits used, see 7.1.4 ISO/IEC 19794-4. */
    acquisitionLevel = dataIn.readUnsignedShort();
    int count = dataIn.readUnsignedByte();
    scaleUnits = dataIn.readUnsignedByte(); /* 1 -> PPI, 2 -> PPCM */
    scanResolutionHorizontal = dataIn.readUnsignedShort();
    scanResolutionVertical = dataIn.readUnsignedShort();
    imageResolutionHorizontal = dataIn.readUnsignedShort(); /* should be <= scanResH */
    imageResolutionVertical = dataIn.readUnsignedShort(); /* should be <= scanResV */
    depth = dataIn.readUnsignedByte(); /* 1 - 16 bits, i.e. 2 - 65546 gray levels */
    compressionAlgorithm = dataIn.readUnsignedByte(); /* 0 Uncompressed, no bit packing
                                                       * 1 Uncompressed, bit packed
                                                       * 2 Compressed, WSQ
                                                       * 3 Compressed, JPEG
                                                       * 4 Compressed, JPEG2000
                                                       * 5 PNG
                                                       */
    /* int RFU = */ dataIn.readUnsignedShort(); /* Should be 0x0000 */

    long headerLength = 4L + 4L + 6L + 2L + 2L + 1L + 1L + 2L + 2L + 2L + 2L + 1L + 1L + 2L;
    long dataLength = recordLength - headerLength;

    long constructedDataLength = 0L;

    for (int i = 0; i < count; i++) {
      FingerImageInfo imageInfo = new FingerImageInfo(inputStream, compressionAlgorithm);
      constructedDataLength += imageInfo.getRecordLength();
      add(imageInfo);
    }
    if (dataLength != constructedDataLength) {
      LOGGER.warning("ConstructedDataLength and dataLength differ: "
          + "dataLength = " + dataLength
          + ", constructedDataLength = " + constructedDataLength);
    }
  }

  /**
   * Writes this finger info to an output stream.
   *
   * @param outputStream an output stream
   *
   * @throws IOException if writing fails
   */
  @Override
  public void writeObject(OutputStream outputStream) throws IOException {

    long headerLength = 32; /* 4 + 4 + 6 + 2 + 2 + 1 + 1 + 2 + 2 + 2 + 2 + 1 + 1 + 2 */

    long dataLength = 0;
    List<FingerImageInfo> fingerImageInfos = getSubRecords();
    for (FingerImageInfo fingerImageInfo: fingerImageInfos) {
      dataLength += fingerImageInfo.getRecordLength();
    }

    long recordLength = headerLength + dataLength;

    /* General record header, should be 32... */

    DataOutputStream dataOut = outputStream instanceof DataOutputStream ? (DataOutputStream)outputStream : new DataOutputStream(outputStream);

    dataOut.writeInt(FORMAT_IDENTIFIER);           /* 4 */
    dataOut.writeInt(VERSION_NUMBER);              /* + 4 = 8 */

    writeLong(recordLength, dataOut, 6);           /* + 6 = 14 */

    dataOut.writeShort(captureDeviceId);           /* + 2 = 16 */
    dataOut.writeShort(acquisitionLevel);          /* + 2 = 18 */
    dataOut.writeByte(fingerImageInfos.size());    /* + 1 = 19 */
    dataOut.writeByte(scaleUnits);                 /* + 1 = 20 */
    dataOut.writeShort(scanResolutionHorizontal);  /* + 2 = 22 */
    dataOut.writeShort(scanResolutionVertical);    /* + 2 = 24 */
    dataOut.writeShort(imageResolutionHorizontal); /* + 2 = 26 */
    dataOut.writeShort(imageResolutionVertical);   /* + 2 = 28 */
    dataOut.writeByte(depth);                      /* + 1 = 29 */

    dataOut.writeByte(compressionAlgorithm);       /* + 1 = 30 */
    dataOut.writeShort(0x0000); /* RFU */          /* + 2 = 32 */

    for (FingerImageInfo fingerImageInfo: fingerImageInfos) {
      fingerImageInfo.writeObject(dataOut);
    }
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + acquisitionLevel;
    result = prime * result + captureDeviceId;
    result = prime * result + compressionAlgorithm;
    result = prime * result + depth;
    result = prime * result + imageResolutionHorizontal;
    result = prime * result + imageResolutionVertical;
    result = prime * result + ((sbh == null) ? 0 : sbh.hashCode());
    result = prime * result + scaleUnits;
    result = prime * result + scanResolutionHorizontal;
    result = prime * result + scanResolutionVertical;
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

    FingerInfo other = (FingerInfo)obj;
    return acquisitionLevel == other.acquisitionLevel
        && captureDeviceId == other.captureDeviceId
        && compressionAlgorithm == other.compressionAlgorithm
        && depth == other.depth
        && imageResolutionHorizontal == other.imageResolutionHorizontal
        && imageResolutionVertical == other.imageResolutionVertical
        && scaleUnits == other.scaleUnits
        && scanResolutionHorizontal == other.scanResolutionHorizontal
        && scanResolutionVertical == other.scanResolutionVertical;
  }

  @Override
  public String toString() {
    StringBuilder result = new StringBuilder();
    result.append("FingerInfo [");
    List<FingerImageInfo> records = getSubRecords();
    for (FingerImageInfo record: records) {
      result.append(record.toString());
    }
    result.append("]");
    return result.toString();
  }

  /**
   * Returns the standard biometric header of this biometric data block.
   *
   * @return the standard biometric header
   */
  public StandardBiometricHeader getStandardBiometricHeader() {
    if (sbh == null) {
      byte[] biometricType = { (byte)CBEFFInfo.BIOMETRIC_TYPE_FINGERPRINT };
      byte[] biometricSubtype = { (byte)getBiometricSubtype() };
      byte[] formatOwner = { (byte)((FORMAT_OWNER_VALUE & 0xFF00) >> 8), (byte)(FORMAT_OWNER_VALUE & 0xFF) };
      byte[] formatType = { (byte)((FORMAT_TYPE_VALUE & 0xFF00) >> 8), (byte)(FORMAT_TYPE_VALUE & 0xFF) };

      SortedMap<Integer, byte[]> elements = new TreeMap<Integer, byte[]>();
      elements.put(ISO781611.BIOMETRIC_TYPE_TAG, biometricType);
      elements.put(ISO781611.BIOMETRIC_SUBTYPE_TAG, biometricSubtype);
      elements.put(ISO781611.FORMAT_OWNER_TAG, formatOwner);
      elements.put(ISO781611.FORMAT_TYPE_TAG, formatType);

      sbh = new StandardBiometricHeader(elements);
    }
    return sbh;
  }

  /**
   * Returns the finger image infos embedded in this finger info.
   *
   * @return the embedded finger image infos
   */
  public List<FingerImageInfo> getFingerImageInfos() {
    return getSubRecords();
  }

  /**
   * Adds a finger image info to this finger info.
   *
   * @param fingerImageInfo the finger image info to add
   */
  public void addFingerImageInfo(FingerImageInfo fingerImageInfo) {
    add(fingerImageInfo);
  }

  /**
   * Removes a finger image info from this finger info.
   *
   * @param index the index of the finger image info to remove
   */
  public void removeFingerImageInfo(int index) {
    remove(index);
  }

  /* ONLY PRIVATE BELOW */

  /**
   * Reads a long from a stream.
   *
   * @param inputStream the stream to read from
   * @param byteCount the number of bytes to read
   *
   * @return the resulting long
   *
   * @throws IOException on error reading from the stream
   */
  private static long readUnsignedLong(InputStream inputStream, int byteCount) throws IOException {
    DataInputStream dataIn = inputStream instanceof DataInputStream ? (DataInputStream)inputStream : new DataInputStream(inputStream);
    byte[] buf = new byte[byteCount];
    dataIn.readFully(buf);
    long result = 0L;
    for (int i = 0; i < byteCount; i++) {
      result <<= 8;
      result += buf[i] & 0xFF;
    }
    return result;
  }

  /**
   * Writes a long to a stream.
   *
   * @param value the long value to write
   * @param outputStream the stream to write to
   * @param byteCount the number of bytes to use
   *
   * @throws IOException on error writing to the stream
   */
  private static void writeLong(long value, OutputStream outputStream, int byteCount) throws IOException {
    if (byteCount <= 0) {
      return;
    }

    for (int i = 0; i < (byteCount - 8); i++) {
      outputStream.write(0);
    }
    if (byteCount > 8) {
      byteCount = 8;
    }
    for (int i = (byteCount - 1); i >= 0; i--) {
      long mask = 0xFFL << (i * 8);
      byte b = (byte)((value & mask) >> (i * 8));
      outputStream.write(b);
    }
  }

  /**
   * Converts an image data type code to a mime-type.
   * Compression algorithm codes based on Table 3 in Section 7.1.13 of 19794-4.
   *
   * 0 Uncompressed, no bit packing
   * 1 Uncompressed, bit packed
   * 2 Compressed, WSQ
   * 3 Compressed, JPEG
   * 4 Compressed, JPEG2000
   * 5 PNG
   *
   * @param imageDataType an image data type constant, one of
   *        {@code COMPRESSION_UNCOMPRESSED_NO_BIT_PACKING},
   *        {@code COMPRESSION_UNCOMPRESSED_BIT_PACKED},
   *        {@code COMPRESSION_WSQ}, {@code COMPRESSION_JPEG},
   *        {@code COMPRESSION_JPEG2000}, or {@code COMPRESSION_PNG}
   *
   * @return a mime-type string
   */
  static String toMimeType(int imageDataType) {
    switch (imageDataType) {
      case FingerInfo.COMPRESSION_UNCOMPRESSED_NO_BIT_PACKING:
        return "image/raw";
      case FingerInfo.COMPRESSION_UNCOMPRESSED_BIT_PACKED:
        return "image/raw";
      case FingerInfo.COMPRESSION_WSQ:
        return "image/x-wsq";
      case FingerInfo.COMPRESSION_JPEG:
        return "image/jpeg";
      case FingerInfo.COMPRESSION_JPEG2000:
        return "image/jpeg2000";
      case FingerInfo.COMPRESSION_PNG:
        return "image/png";
      default:
        return null;
    }
  }

  /**
   * Converts a mime-type to an image data (compression) type.
   *
   * @param mimeType the mime-type to convert
   *
   * @return the image data (compression) type
   */
  static int fromMimeType(String mimeType) {
    if ("image/x-wsq".equals(mimeType)) {
      return FingerInfo.COMPRESSION_WSQ;
    }
    if ("image/jpeg".equals(mimeType)) {
      return FingerInfo.COMPRESSION_JPEG;
    }
    if ("image/jpeg2000".equals(mimeType)) {
      return FingerInfo.COMPRESSION_JPEG2000;
    }
    if ("images/png".equals(mimeType)) {
      return FingerInfo.COMPRESSION_PNG;
    }

    throw new IllegalArgumentException("Did not recognize mimeType");
  }

  /**
   * Returns the biometric sub-type bit mask for the fingers in this finger info.
   *
   * @return a biometric sub-type bit mask
   */
  private int getBiometricSubtype() {
    int result = CBEFFInfo.BIOMETRIC_SUBTYPE_NONE;
    boolean isFirst = true;
    List<FingerImageInfo> fingerImageInfos = getSubRecords();
    for (FingerImageInfo fingerImageInfo: fingerImageInfos) {
      int fingerImageInfoSubType = fingerImageInfo.getBiometricSubtype();
      if (isFirst) {
        result = fingerImageInfoSubType;
        isFirst = false;
      } else {
        result &= fingerImageInfoSubType;
      }
    }
    return result;
  }
}
