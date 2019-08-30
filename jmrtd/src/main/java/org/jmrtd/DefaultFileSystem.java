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
 * $Id: DefaultFileSystem.java 1799 2018-10-30 16:25:48Z martijno $
 */

package org.jmrtd;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.jmrtd.io.FragmentBuffer;
import org.jmrtd.io.FragmentBuffer.Fragment;
import org.jmrtd.lds.CVCAFile;
import org.jmrtd.lds.LDSFileUtil;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.FileInfo;
import net.sf.scuba.smartcards.FileSystemStructured;
import net.sf.scuba.tlv.TLVInputStream;

/**
 * A file system for ICAO MRTDs (and similar file systems).
 * This translates abstract high level selection and read binary commands to
 * concrete low level file related APDUs which are sent to the ICC through the
 * card service.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1799 $
 *
 * @since 0.7.0
 */
public class DefaultFileSystem implements FileSystemStructured {

  /** Invalid short identifier. */
  public static final int NO_SFI = -1;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /** Number of bytes to read at start of file to determine file length. */
  private static final int READ_AHEAD_LENGTH = 8;

  /** Indicates the file that is (or should be) selected. */
  private short selectedFID;

  private boolean isSFIEnabled;

  /**
   * A boolean indicating whether we actually already
   * sent the SELECT command to select {@ code selectedFID}.
   */
  private boolean isSelected;

  private APDULevelReadBinaryCapable service;

  private Map<Short, DefaultFileInfo> fileInfos;

  private Map<Short, Byte> fidToSFI;

  private APDUWrapper wrapper;

  /**
   * Creates a file system.
   *
   * @param service the card service supporting low-level {@code SELECT} and/or {@code READ BINARY} commands
   * @param isSFIEnabled whether the file system should use short file identifiers in {@code READ BINARY} commands
   */
  public DefaultFileSystem(APDULevelReadBinaryCapable service, boolean isSFIEnabled) {
    this(service, isSFIEnabled, LDSFileUtil.FID_TO_SFI);
  }

  /**
   * Creates a file system.
   *
   * @param service the card service supporting low-level {@code SELECT} and/or {@code READ BINARY} commands
   * @param isSFIEnabled whether the file system should use short file identifiers in {@code READ BINARY} commands
   * @param fidToSFI maps file identifiers to short file identifiers
   */
  public DefaultFileSystem(APDULevelReadBinaryCapable service, boolean isSFIEnabled, Map<Short, Byte> fidToSFI) {
    this.service = service;
    this.fileInfos = new HashMap<Short, DefaultFileInfo>();
    this.selectedFID = 0;
    this.isSelected = false;
    this.isSFIEnabled = isSFIEnabled;
    this.fidToSFI = fidToSFI;
  }

  /**
   * Sets the current wrapper to the given APDU wrapper.
   * Subsequent APDUs will be wrapped before sending to the ICC.
   *
   * @param wrapper an APDU wrapper
   */
  public void setWrapper(APDUWrapper wrapper) {
    this.wrapper = wrapper;
  }

  /**
   * Returns the selected path.
   *
   * @return the path components
   *
   * @throws CardServiceException on error
   */
  public synchronized FileInfo[] getSelectedPath() throws CardServiceException {
    DefaultFileInfo fileInfo = getFileInfo();
    if (fileInfo == null) {
      return null;
    } else {
      return new DefaultFileInfo[] { fileInfo };
    }
  }

  /*
   * NOTE: This doesn't actually send a select file command. ReadBinary will do so
   * if needed.
   */
  /**
   * Selects a file.
   *
   * @param fid indicates the file to select
   *
   * @throws CardServiceException on error communicating over the service
   */
  public synchronized void selectFile(short fid) throws CardServiceException {
    if (selectedFID == fid) {
      return;
    }

    selectedFID = fid;
    isSelected = false;
  }

  /**
   * Reads a block of bytes.
   *
   * @param offset offset index in the selected file
   * @param length the number of bytes to read
   *
   * @return a copy of the bytes read
   *
   * @throws CardServiceException on error
   */
  public synchronized byte[] readBinary(int offset, int length) throws CardServiceException {
    DefaultFileInfo fileInfo = null;
    try {
      if (selectedFID <= 0) {
        throw new CardServiceException("No file selected");
      }

      /* Check buffer to see if we already have some of the bytes. */
      fileInfo = getFileInfo();
      if (fileInfo == null) {
        throw new IllegalStateException("Could not get file info");
      }
      Fragment fragment = fileInfo.getSmallestUnbufferedFragment(offset, length);

      int responseLength = length;

      byte[] bytes = null;
      if (fragment.getLength() > 0) {
        if (isSFIEnabled && offset < 256) {
          Byte sfi = fidToSFI.get(selectedFID);
          if (sfi == null) {
            throw new NumberFormatException("Unknown FID " + Integer.toHexString(selectedFID));
          }
          bytes = sendReadBinary(0x80 | (sfi & 0xFF), fragment.getOffset(), fragment.getLength(), false);
          isSelected = true;
        } else {
          if (!isSelected) {
            sendSelectFile(selectedFID);
            isSelected = true;
          }
          bytes = sendReadBinary(fragment.getOffset(), fragment.getLength(), offset > 32767);
        }

        if (bytes == null) {
          throw new IllegalStateException("Could not read bytes");
        }

        if (bytes.length > 0) {
          /* Update buffer with newly read bytes. */
          fileInfo.addFragment(fragment.getOffset(), bytes);
        }

        /*
         * If we request a block of data, create the return buffer from the actual response length, not the requested Le.
         * The latter causes issues when the returned block has a one byte padding (only 0x80) which ends up being removed but
         * the length is not kept track of, leaving an unwanted 0-byte at the end of the data block, which now has a length
         * of Le, but actually contained Le - 1 data bytes.
         *
         * Bug reproduced using org.jmrtd.AESSecureMessagingWrapper with AES-256.
         */

        responseLength = bytes.length;
      }
      /* Shrink wrap the bytes that are now buffered. */
      /* NOTE: That arraycopy looks costly, consider using dest array and offset params instead of byte[] result... -- MO */
      byte[] buffer = fileInfo.getBuffer();

      byte[] result = new byte[responseLength];
      System.arraycopy(buffer, offset, result, 0, responseLength);

      return result;
    } catch (CardServiceException cse) {
      throw new CardServiceException("Read binary failed on file " + (fileInfo == null ? Integer.toHexString(selectedFID) : fileInfo), cse, cse.getSW());
    } catch (Exception e) {
      throw new CardServiceException("Read binary failed on file " + (fileInfo == null ? Integer.toHexString(selectedFID) : fileInfo), e);
    }
  }

  /**
   * Returns the file info object for the currently selected file. If this
   * executes normally the result is non-null. If the file has not been
   * read before this will send a READ_BINARY to determine length.
   *
   * @return a non-null MRTDFileInfo
   *
   * @throws CardServiceException on error
   */
  private synchronized DefaultFileInfo getFileInfo() throws CardServiceException {
    if (selectedFID <= 0) {
      throw new CardServiceException("No file selected");
    }

    DefaultFileInfo fileInfo = fileInfos.get(selectedFID);

    /* If known file, use file info from cache. */
    if (fileInfo != null) {
      return fileInfo;
    }

    /* Not cached, actually read some bytes to determine file info. */
    try {
      /*
       * Each passport file consists of a TLV structure, read ahead to determine length.
       * EF.CVCA is the exception and has a fixed length of CVCAFile.LENGTH.
       */
      byte[] prefix = null;
      if (isSFIEnabled) {
        Byte sfi = fidToSFI.get(selectedFID);
        if (sfi == null) {
          throw new NumberFormatException("Unknown FID " + Integer.toHexString(selectedFID));
        }
        prefix = sendReadBinary(0x80 | (sfi & 0XFF), 0, READ_AHEAD_LENGTH, false);
        isSelected = true;
      } else {
        if (!isSelected) {
          sendSelectFile(selectedFID);
          isSelected = true;
        }
        prefix = sendReadBinary(0, READ_AHEAD_LENGTH, false);
      }
      if (prefix == null || prefix.length != READ_AHEAD_LENGTH) {
        LOGGER.warning("Something is wrong with prefix, prefix = " + Arrays.toString(prefix));
        return null;
      }
      ByteArrayInputStream baInputStream = new ByteArrayInputStream(prefix);
      TLVInputStream tlvInputStream = new TLVInputStream(baInputStream);
      try {
        int fileLength = 0;
        int tag = tlvInputStream.readTag();
        if (tag == CVCAFile.CAR_TAG) {
          fileLength = CVCAFile.LENGTH;
        } else {
          int vLength = tlvInputStream.readLength();
          int tlLength = prefix.length - baInputStream.available(); /* NOTE: we're using a specific property of ByteArrayInputStream's available method here! */
          fileLength = tlLength + vLength;
        }
        fileInfo = new DefaultFileInfo(selectedFID, fileLength);
        fileInfo.addFragment(0, prefix);
        fileInfos.put(selectedFID, fileInfo);
        return fileInfo;
      } finally {
        tlvInputStream.close();
      }
    } catch (IOException ioe) {
      throw new CardServiceException("Error getting file info for " + Integer.toHexString(selectedFID), ioe);
    }
  }

  /**
   * Selects a file within the MRTD application.
   *
   * @param fid a file identifier
   *
   * @throws CardServiceException on error
   */
  public synchronized void sendSelectFile(short fid) throws CardServiceException {
    service.sendSelectFile(wrapper, fid);
  }

  /**
   * Sends a {@code READ BINARY} command using a short file identifier to the passport,
   * using the wrapper when a secure channel has been set up.
   *
   * @param offset offset into the file
   * @param le the expected length of the file to read
   * @param isTLVEncodedOffsetNeeded whether to encode the offset in a TLV object (typically for offset larger than 32767)
   *
   * @return a byte array of length {@code le} with (the specified part of) the contents of the currently selected file
   *
   * @throws CardServiceException on tranceive error
   */
  public synchronized byte[] sendReadBinary(int offset, int le, boolean isTLVEncodedOffsetNeeded) throws CardServiceException {
    return service.sendReadBinary(wrapper, NO_SFI, offset, le, false, isTLVEncodedOffsetNeeded);
  }

  /**
   * Sends a {@code READ BINARY} command using a short file identifier to the passport,
   * using the wrapper when a secure channel has been set up.
   *
   * @param sfi the short file identifier byte as int value (between 0 and 255)
   * @param offset offset into the file
   * @param le the expected length of the file to read
   * @param isTLVEncodedOffsetNeeded whether to encode the offset in a TLV object (typically for offset larger than 32767)
   *
   * @return a byte array of length {@code le} with (the specified part of) the contents of the currently selected file
   *
   * @throws CardServiceException on tranceive error
   */
  public synchronized byte[] sendReadBinary(int sfi, int offset, int le, boolean isTLVEncodedOffsetNeeded) throws CardServiceException {
    return service.sendReadBinary(wrapper, sfi, offset, le, true, isTLVEncodedOffsetNeeded);
  }

  /**
   * A file info for the ICAO MRTD file system.
   *
   * @author The JMRTD team (info@jmrtd.org)
   *
   * @version $Revision: 1799 $
   */
  private static class DefaultFileInfo extends FileInfo implements Serializable {

    private static final long serialVersionUID = 6727369753765119839L;

    private short fid;
    private FragmentBuffer buffer;

    /**
     * Constructs a file info.
     *
     * @param fid indicates which file
     * @param length length of the contents of the file
     */
    public DefaultFileInfo(short fid, int length) {
      this.fid = fid;
      this.buffer = new FragmentBuffer(length);
    }

    /**
     * Returns the buffer.
     *
     * @return the buffer
     */
    public byte[] getBuffer() {
      return buffer.getBuffer();
    }

    /**
     * Returns the file identifier.
     *
     * @return file identifier
     */
    @Override
    public short getFID() {
      return fid;
    }

    /**
     * Returns the length of the file.
     *
     * @return the length of the file
     */
    @Override
    public int getFileLength() {
      return buffer.getLength();
    }

    /**
     * Returns a textual representation of this file info.
     *
     * @return a textual representation of this file info
     */
    @Override
    public String toString() {
      return Integer.toHexString(fid);
    }

    /**
     * Returns the smallest unbuffered fragment included in <code>offset</code> and <code>offset + length - 1</code>.
     *
     * @param offset the offset
     * @param length the length
     *
     * @return a fragment smaller than or equal to the fragment indicated by <code>offset</code> and <code>length</code>
     */
    public Fragment getSmallestUnbufferedFragment(int offset, int length) {
      return buffer.getSmallestUnbufferedFragment(offset, length);
    }

    /**
     * Adds a fragment of bytes at a specific offset to this file.
     *
     * @param offset the offset
     * @param bytes the bytes to be added
     */
    public void addFragment(int offset, byte[] bytes) {
      buffer.addFragment(offset, bytes);
    }
  }
}
