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
 * $Id: DisplayedImageDataGroup.java 1808 2019-03-07 21:32:19Z martijno $
 */

package org.jmrtd.lds;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVOutputStream;

/**
 * File structure image template files that can be displayed.
 * Abstract super class for ICAO LDS EF_DG5 - EF_DG7.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1808 $
 */
public abstract class DisplayedImageDataGroup extends DataGroup {

  private static final long serialVersionUID = 5994136177872308962L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private static final int DISPLAYED_IMAGE_COUNT_TAG = 0x02;

  private int displayedImageTagToUse;
  private List<DisplayedImageInfo> imageInfos;

  /**
   * Constructs a displayed image data group from a list of displayed images.
   * The list should not be {@code null} or contain {@code null} valued displayed images.
   *
   * @param dataGroupTag a tag indicating DG5, DG6, or DG7
   * @param imageInfos a list of displayed images
   * @param displayedImageTagToUse a tag indicating <i>Portrait</i> or <i>Signature or mark</i>
   */
  public DisplayedImageDataGroup(int dataGroupTag, List<DisplayedImageInfo> imageInfos, int displayedImageTagToUse) {
    super(dataGroupTag);
    if (imageInfos == null) {
      throw new IllegalArgumentException("imageInfos cannot be null");
    }
    this.displayedImageTagToUse = displayedImageTagToUse;
    this.imageInfos = new ArrayList<DisplayedImageInfo>(imageInfos);
    checkTypesConsistentWithTag();
  }

  /**
   * Constructs a displayed image data group from binary representation.
   *
   * @param dataGroupTag a tag indicating DG5, DG6, or DG7
   * @param inputStream an input stream
   *
   * @throws IOException on error reading the input stream
   */
  public DisplayedImageDataGroup(int dataGroupTag, InputStream inputStream) throws IOException {
    super(dataGroupTag, inputStream);
    if (this.imageInfos == null) {
      this.imageInfos = new ArrayList<DisplayedImageInfo>();
    }
    checkTypesConsistentWithTag();
  }

  @Override
  protected void readContent(InputStream inputStream) throws IOException {
    TLVInputStream tlvIn = inputStream instanceof TLVInputStream ? (TLVInputStream)inputStream : new TLVInputStream(inputStream);
    int countTag = tlvIn.readTag();
    if (countTag != DISPLAYED_IMAGE_COUNT_TAG) { /* 02 */
      throw new IllegalArgumentException("Expected tag 0x02 in displayed image structure, found " + Integer.toHexString(countTag));
    }
    int countLength = tlvIn.readLength();
    if (countLength != 1) {
      throw new IllegalArgumentException("DISPLAYED_IMAGE_COUNT should have length 1");
    }
    int count = (tlvIn.readValue()[0] & 0xFF);
    for (int i = 0; i < count; i++) {
      DisplayedImageInfo imageInfo = new DisplayedImageInfo(tlvIn);
      if (i == 0) {
        displayedImageTagToUse = imageInfo.getDisplayedImageTag();
      } else if (imageInfo.getDisplayedImageTag() != displayedImageTagToUse){
        throw new IOException("Found images with different displayed image tags inside displayed image datagroup");
      }
      add(imageInfo);
    }
  }

  /**
   * Writes the contents of this structure to a stream.
   *
   * @param outputStream the stream to write to
   *
   * @throws IOException on error writing to the stream
   */
  @Override
  protected void writeContent(OutputStream outputStream) throws IOException {
    TLVOutputStream tlvOut = outputStream instanceof TLVOutputStream ? (TLVOutputStream)outputStream : new TLVOutputStream(outputStream);
    tlvOut.writeTag(DISPLAYED_IMAGE_COUNT_TAG);
    tlvOut.writeValue(new byte[] { (byte)imageInfos.size() });
    for (DisplayedImageInfo imageInfo: imageInfos) {
      imageInfo.writeObject(tlvOut);
    }
  }

  @Override
  public String toString() {
    StringBuilder result = new StringBuilder();
    result.append(getClass().getSimpleName());
    result.append(" [");
    boolean isFirst = true;
    if (imageInfos == null) {
      throw new IllegalStateException("imageInfos cannot be null");
    }
    for (DisplayedImageInfo info: imageInfos) {
      if (isFirst) {
        isFirst = false;
      } else {
        result.append(", ");
      }
      result.append(info.toString());
    }
    result.append("]");
    return result.toString();
  }

  @Override
  public int hashCode() {
    return 1337 + (imageInfos == null ? 1 : imageInfos.hashCode()) + 31337;
  }

  @Override
  public boolean equals(Object other) {
    if (other == null) {
      return false;
    }
    if (other == this) {
      return true;
    }
    if (!getClass().equals(other.getClass())) {
      return false;
    }

    DisplayedImageDataGroup otherDG = (DisplayedImageDataGroup)other;
    return this.imageInfos == otherDG.imageInfos || this.imageInfos != null && this.imageInfos.equals(otherDG.imageInfos);
  }

  /**
   * Returns the image infos.
   *
   * @return images
   */
  public List<DisplayedImageInfo> getImages() {
    return new ArrayList<DisplayedImageInfo>(imageInfos);
  }

  /**
   * Adds an image info to this data group.
   *
   * @param image the image to add
   */
  private void add(DisplayedImageInfo image) {
    if (imageInfos == null) {
      imageInfos = new ArrayList<DisplayedImageInfo>();
    }
    imageInfos.add(image);
  }

  /**
   * Checks whether the type of image infos is consistent with the type
   * and throws an {@code IllegalArgumentException} if not.
   */
  private void checkTypesConsistentWithTag() {
    for (DisplayedImageInfo imageInfo: imageInfos) {
      if (imageInfo == null) {
        throw new IllegalArgumentException("Found a null image info");
      }
      switch (imageInfo.getType()) {
        case ImageInfo.TYPE_SIGNATURE_OR_MARK:
          if (displayedImageTagToUse != DisplayedImageInfo.DISPLAYED_SIGNATURE_OR_MARK_TAG) {
            throw new IllegalArgumentException("\'Portrait\' image cannot be part of a \'Signature or usual mark\' displayed image datagroup");
          }
          break;
        case ImageInfo.TYPE_PORTRAIT:
          if (displayedImageTagToUse != DisplayedImageInfo.DISPLAYED_PORTRAIT_TAG) {
            throw new IllegalArgumentException("\'Signature or usual mark\' image cannot be part of a \'Portrait\' displayed image datagroup");
          }
          break;
        default:
          LOGGER.warning("Unsupported image type");
          break;
      }
    }
  }
}
