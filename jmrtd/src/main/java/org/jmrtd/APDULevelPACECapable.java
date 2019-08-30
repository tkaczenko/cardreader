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
 * $Id: APDULevelPACECapable.java 1818 2019-08-02 12:59:22Z martijno $
 */

package org.jmrtd;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardServiceException;

/**
 * The low-level capability of sending APDUs for the PACE protocol.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1818 $
 */
public interface APDULevelPACECapable {

  /**
   * The MSE AT APDU for PACE, see ICAO TR-SAC-1.01, Section 3.2.1, BSI TR 03110 v2.03 B11.1.
   * Note that (for now) caller is responsible for prefixing the byte[] params with specified tags.
   *
   * @param wrapper secure messaging wrapper
   * @param oid OID of the protocol to select (this method will prefix {@code 0x80})
   * @param refPublicKeyOrSecretKey value specifying whether to use MRZ ({@code 0x01}) or CAN ({@code 0x02}) (this method will prefix {@code 0x83})
   * @param refPrivateKeyOrForComputingSessionKey indicates a private key or reference for computing a session key (this method will prefix {@code 0x84})
   *
   * @throws CardServiceException on error
   */
  void sendMSESetATMutualAuth(APDUWrapper wrapper, String oid, int refPublicKeyOrSecretKey, byte[] refPrivateKeyOrForComputingSessionKey) throws CardServiceException;

  /**
   * Sends a General Authenticate command.
   *
   * @param wrapper secure messaging wrapper
   * @param data data to be sent, without the {@code 0x7C} prefix (this method will add it)
   * @param le the length to request
   * @param isLast indicates whether this is the last command in the chain
   *
   * @return dynamic authentication data without the {@code 0x7C} prefix (this method will remove it)
   *
   * @throws CardServiceException on error
   */
  byte[] sendGeneralAuthenticate(APDUWrapper wrapper, byte[] data, int le, boolean isLast) throws CardServiceException;
}
