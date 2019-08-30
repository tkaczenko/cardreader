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
 * $Id: APDULevelReadBinaryCapable.java 1781 2018-05-25 11:41:48Z martijno $
 */

package org.jmrtd;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardServiceException;

/**
 * The low-level capability for reading files using {@code SELECT} and {@code READ BINARY}
 * (both SFI and non-SFI) commands.
 *
 * The actual file system on an ICAO compliant chip supports this.
 *
 * @author The JMRTD team (info@jmrtd,org)
 *
 * @version $Revision: 1781 $
 *
 * @since 0.7.0
 */
public interface APDULevelReadBinaryCapable {

  /**
   * Sends a {@code SELECT APPLET} command to the card.
   *
   * @param wrapper the secure messaging wrapper to use
   * @param aid the applet to select
   *
   * @throws CardServiceException on tranceive error
   */
  void sendSelectApplet(APDUWrapper wrapper, byte[] aid) throws CardServiceException;

  /**
   * Selects a file by file identifier.
   *
   * @param wrapper the APDU wrapper to use
   * @param fid the file identifier
   *
   * @throws CardServiceException on error
   */
  void sendSelectFile(APDUWrapper wrapper, short fid) throws CardServiceException;

  /**
   * Sends a {@code READ BINARY} command to the passport.
   * Secure messaging will be applied to the command and response APDU.
   *
   * @param wrapper the secure messaging wrapper to use, or {@code null} for none
   * @param sfi the short file identifier byte of the file to read as an int value (between 0 and 255)
   *            only if {@code isSFIEnabled} is {@code true}, if not any value)
   * @param offset offset into the file
   *        (either a value between 0 and 255 if {@code isSFIEnabled} holds,
   *        or a value between 0 and 65535 if not)
   * @param le the expected length of the file to read
   * @param isSFIEnabled a boolean indicating whether short file identifiers are used
   * @param isTLVEncodedOffsetNeeded a boolean indicating whether it should be a long ({@code INS == 0xB1}) read
   *
   * @return a byte array of length at most {@code le} with (the specified part of) the contents of the currently selected file
   *
   * @throws CardServiceException if the command was not successful
   */
  byte[] sendReadBinary(APDUWrapper wrapper, int sfi, int offset, int le, boolean isSFIEnabled, boolean isTLVEncodedOffsetNeeded) throws CardServiceException;
}
