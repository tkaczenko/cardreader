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
 * $Id: DisplayedImageInfo.java 1766 2018-02-20 11:33:20Z martijno $
 */

package org.jmrtd.lds;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVOutputStream;
import net.sf.scuba.tlv.TLVUtil;

/**
 * Data structure for storing either a <i>Portrait</i> (as used in DG5) or
 * a <i>Signature or mark</i> (as used in DG7).
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1766 $
 */
public class DisplayedImageInfo extends AbstractImageInfo {

  private static final long serialVersionUID = 3801320585294302721L;

  public static final int DISPLAYED_PORTRAIT_TAG = 0x5F40;

  public static final int DISPLAYED_SIGNATURE_OR_MARK_TAG = 0x5F43;

  private int displayedImageTag;

  /**
   * Constructs a displayed image info from the image bytes.
   *
   * @param type one of {@link ImageInfo#TYPE_PORTRAIT} or {@link ImageInfo#TYPE_SIGNATURE_OR_MARK}
   * @param imageBytes encoded image, for <i>Portrait</i> and <i>Signature or mark</i> use JPEG encoding
   */
  public DisplayedImageInfo(int type, byte[] imageBytes) {
    super(type, getMimeTypeFromType(type));
    displayedImageTag = getDisplayedImageTagFromType(type);
    setImageBytes(imageBytes);
  }

  /**
   * Constructs a displayed image info from binary encoding.
   *
   * @param in an input stream
   *
   * @throws IOException if decoding fails
   */
  public DisplayedImageInfo(InputStream in) throws IOException {
    readObject(in);
  }

  /**
   * Reads the displayed image. This method should be implemented by concrete
   * subclasses. The 5F2E or 7F2E tag and the length are already read.
   *
   * @param inputStream the input stream positioned so that biometric data block tag and length are already read
   *
   * @throws IOException if reading fails
   */
  @Override
  protected void readObject(InputStream inputStream) throws IOException {
    TLVInputStream tlvIn = inputStream instanceof TLVInputStream ? (TLVInputStream)inputStream : new TLVInputStream(inputStream);

    displayedImageTag = tlvIn.readTag();
    if (displayedImageTag != DISPLAYED_PORTRAIT_TAG /* 5F40 */
        && displayedImageTag != DISPLAYED_SIGNATURE_OR_MARK_TAG /* 5F43 */) {
      throw new IllegalArgumentException("Expected tag 0x5F40 or 0x5F43, found " + Integer.toHexString(displayedImageTag));
    }

    int type = getTypeFromDisplayedImageTag(displayedImageTag);
    setType(type);
    setMimeType(getMimeTypeFromType(type));

    long imageLength = tlvIn.readLength();

    readImage(tlvIn, imageLength);
  }

  @Override
  protected void writeObject(OutputStream outputStream) throws IOException {
    TLVOutputStream tlvOut = outputStream instanceof TLVOutputStream ? (TLVOutputStream)outputStream : new TLVOutputStream(outputStream);
    tlvOut.writeTag(getDisplayedImageTagFromType(getType()));
    writeImage(tlvOut);
    tlvOut.writeValueEnd();
  }

  /**
   * Returns the displayed image tag.
   * Either {@link #DISPLAYED_PORTRAIT_TAG} or {@link #DISPLAYED_SIGNATURE_OR_MARK_TAG},
   * depending on the type of image.
   *
   * @return the displayed image tag
   */
  int getDisplayedImageTag() {
    return displayedImageTag;
  }

  /**
   * Returns the record length of the encoded image info.
   *
   * @return the record length of the encoded image info
   */
  public long getRecordLength() {
    long length = 0;
    int imageLength = getImageLength();
    length += TLVUtil.getTagLength(getDisplayedImageTagFromType(getType()));
    length += TLVUtil.getLengthLength(imageLength);
    length += imageLength;
    return length;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + displayedImageTag;
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

    DisplayedImageInfo other = (DisplayedImageInfo)obj;
    return displayedImageTag == other.displayedImageTag;
  }

  /* ONLY PRIVATE METHODS BELOW */

  /**
   * As per A1.11.4 in Doc 9303 Part 3 Vol 2:
   *
   * <ul>
   *   <li>Displayed Facial Image: ISO 10918, JFIF option.</li>
   *   <li>Displayed Finger: ANSI/NIST-ITL 1-2000.</li>
   *   <li>Displayed Signature/ usual mark: ISO 10918, JFIF option.</li>
   * </ul>
   *
   * @param type the type
   *
   * @return the mime-type
   */
  private static String getMimeTypeFromType(int type) {
    switch (type) {
      case TYPE_PORTRAIT:
        return "image/jpeg";
      case TYPE_FINGER:
        return "image/x-wsq";
      case TYPE_SIGNATURE_OR_MARK:
        return "image/jpeg";
      default:
        throw new NumberFormatException("Unknown type: " + Integer.toHexString(type));
    }
  }

  /**
   * Derives the displayed image info tag from the image type.
   *
   * @param type the image type, either {@link #TYPE_PORTRAIT} or {@link #TYPE_SIGNATURE_OR_MARK}
   *
   * @return the corresponding image info tag
   */
  private static int getDisplayedImageTagFromType(int type) {
    switch (type) {
      case TYPE_PORTRAIT:
        return DISPLAYED_PORTRAIT_TAG;
      case TYPE_SIGNATURE_OR_MARK:
        return DISPLAYED_SIGNATURE_OR_MARK_TAG;
      default:
        throw new NumberFormatException("Unknown type: " + Integer.toHexString(type));
    }
  }

  /**
   * Derives the image info type from the given tag.
   *
   * @param tag a tag, either {@link #DISPLAYED_PORTRAIT_TAG} or {@link #DISPLAYED_SIGNATURE_OR_MARK_TAG}
   *
   * @return the corresponding image info type
   */
  private static int getTypeFromDisplayedImageTag(int tag) {
    switch (tag) {
      case DISPLAYED_PORTRAIT_TAG:
        return ImageInfo.TYPE_PORTRAIT;
      case DISPLAYED_SIGNATURE_OR_MARK_TAG:
        return ImageInfo.TYPE_SIGNATURE_OR_MARK;
      default:
        throw new NumberFormatException("Unknown tag: " + Integer.toHexString(tag));
    }
  }
}
