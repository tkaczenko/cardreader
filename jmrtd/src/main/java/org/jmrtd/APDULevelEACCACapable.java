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
 * $Id: APDULevelEACCACapable.java 1802 2018-11-06 16:29:28Z martijno $
 */

package org.jmrtd;

import java.math.BigInteger;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardServiceException;

/**
 * The low-level capability of sending APDUs for the (EAC) Chip Authentication protocol (version 1).
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1802 $
 */
public interface APDULevelEACCACapable {

  /**
   * The MSE KAT APDU, see EAC 1.11 spec, Section B.1.
   *
   * @param wrapper secure messaging wrapper
   * @param keyData key data object (tag 0x91)
   * @param idData key id data object (tag 0x84), can be null
   *
   * @throws CardServiceException on error
   */
  void sendMSEKAT(APDUWrapper wrapper, byte[] keyData, byte[] idData) throws CardServiceException;

  /**
   * The  MSE Set AT for Chip Authentication.
   *
   * @param wrapper secure messaging wrapper
   * @param oid the OID
   * @param keyId the keyId or {@code null}
   *
   * @throws CardServiceException on error
   */
  void sendMSESetATIntAuth(APDUWrapper wrapper, String oid, BigInteger keyId) throws CardServiceException;

  /**
   * Sends a General Authenticate command.
   *
   * @param wrapper secure messaging wrapper
   * @param data data to be sent, without the {@code 0x7C} prefix (this method will add it)
   * @param isLast indicates whether this is the last command in the chain
   *
   * @return dynamic authentication data without the {@code 0x7C} prefix (this method will remove it)
   *
   * @throws CardServiceException on error
   */
  byte[] sendGeneralAuthenticate(APDUWrapper wrapper, byte[] data, boolean isLast) throws CardServiceException;
}
