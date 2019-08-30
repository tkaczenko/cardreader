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
 * $Id: APDULevelEACTACapable.java 1781 2018-05-25 11:41:48Z martijno $
 */

package org.jmrtd;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardServiceException;

/**
 * The low-level capability of sending APDUs for the (EAC) Terminal Authentication protocol.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1781 $
 */
public interface APDULevelEACTACapable {

  /**
   * The MSE DST APDU, see EAC 1.11 spec, Section B.2.
   *
   * @param wrapper secure messaging wrapper
   * @param data public key reference data object (tag 0x83)
   *
   * @throws CardServiceException on error
   */
  void sendMSESetDST(APDUWrapper wrapper, byte[] data) throws CardServiceException;

  /**
   * Sends a perform security operation command in extended length mode.
   *
   * @param wrapper secure messaging wrapper
   * @param certBodyData the certificate body
   * @param certSignatureData signature data
   *
   * @throws CardServiceException on error communicating over the service
   */
  void sendPSOExtendedLengthMode(APDUWrapper wrapper, byte[] certBodyData, byte[] certSignatureData) throws CardServiceException;

  /**
   * The MSE Set AT APDU for TA, see EAC 1.11 spec, Section B.2.
   * MANAGE SECURITY ENVIRONMENT command with SET Authentication Template function.
   *
   * Note that caller is responsible for prefixing the byte[] params with specified tags.
   *
   * @param wrapper secure messaging wrapper
   * @param data public key reference data object (should already be prefixed with tag 0x83)
   *
   * @throws CardServiceException on error
   */
  void sendMSESetATExtAuth(APDUWrapper wrapper, byte[] data) throws CardServiceException;

  /**
   * Sends a {@code GET CHALLENGE} command to the passport.
   *
   * @param wrapper secure messaging wrapper
   *
   * @return a byte array of length 8 containing the challenge
   *
   * @throws CardServiceException on tranceive error
   */
  byte[] sendGetChallenge(APDUWrapper wrapper) throws CardServiceException;

  /**
   * Sends the EXTERNAL AUTHENTICATE command.
   * This is used in EAC-TA.
   *
   * @param wrapper secure messaging wrapper
   * @param signature terminal signature
   *
   * @throws CardServiceException if the resulting status word different from 9000
   */
  void sendMutualAuthenticate(APDUWrapper wrapper, byte[] signature) throws CardServiceException;
}
