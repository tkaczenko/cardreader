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
 * $Id: APDULevelBACCapable.java 1781 2018-05-25 11:41:48Z martijno $
 */

package org.jmrtd;

import javax.crypto.SecretKey;

import net.sf.scuba.smartcards.CardServiceException;

/**
 * The low-level capability of sending APDUs for the BAC protocol.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1781 $
 */
public interface APDULevelBACCapable {

  /**
   * Sends a {@code GET CHALLENGE} command to the passport.
   *
   * @return a byte array of length 8 containing the challenge
   *
   * @throws CardServiceException on tranceive error
   */
  byte[] sendGetChallenge() throws CardServiceException;

  /**
   * Sends an {@code EXTERNAL AUTHENTICATE} command to the passport.
   * This is part of BAC.
   * The resulting byte array has length 32 and contains {@code rndICC}
   * (first 8 bytes), {@code rndIFD} (next 8 bytes), their key material
   * {@code kICC} (last 16 bytes).
   *
   * @param rndIFD our challenge
   * @param rndICC their challenge
   * @param kIFD our key material
   * @param kEnc the static encryption key
   * @param kMac the static mac key
   *
   * @return a byte array of length 32 containing the response that was sent
   *         by the passport, decrypted (using {@code kEnc}) and verified
   *         (using {@code kMac})
   *
   * @throws CardServiceException on tranceive error
   */
  byte[] sendMutualAuth(byte[] rndIFD, byte[] rndICC, byte[] kIFD, SecretKey kEnc, SecretKey kMac) throws CardServiceException;
}
