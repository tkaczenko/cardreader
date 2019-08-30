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
 * $Id: PACEKeySpec.java 1816 2019-07-15 13:02:26Z martijno $
 */

package org.jmrtd;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import org.jmrtd.protocol.PACEProtocol;

import net.sf.scuba.util.Hex;

/**
 * A key for PACE, can be CAN, MRZ, PIN, or PUK.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1816 $
 *
 * (Contributions by g.giorkhelidze.)
 */
public class PACEKeySpec implements AccessKeySpec {

  private static final long serialVersionUID = -7113246293247012560L;

  private byte[] key;

  private byte keyReference;

  /**
   * Constructs a PACE key from a string value.
   *
   * @param key the string value containing CAN, PIN or PUK
   * @param keyReference indicates the type of key, valid values are
   *                     {@code MRZ_PACE_KEY_REFERENCE}, {@code CAN_PACE_KEY_REFERENCE},
   *                     {@code PIN_PACE_KEY_REFERENCE}, {@code PUK_PACE_KEY_REFERENCE}
   */
  public PACEKeySpec(String key, byte keyReference) {
    this(Util.getBytes(key), keyReference);
  }

  /**
   * Constructs a key.
   *
   * @param key CAN, MRZ, PIN, PUK password bytes
   * @param keyReference indicates the type of key, valid values are
   *                     {@code MRZ_PACE_KEY_REFERENCE}, {@code CAN_PACE_KEY_REFERENCE},
   *                     {@code PIN_PACE_KEY_REFERENCE}, {@code PUK_PACE_KEY_REFERENCE}
   */
  public PACEKeySpec(byte[] key, byte keyReference) {
    super();
    this.keyReference = keyReference;
    this.key = key;
  }

  /**
   * Creates a PACE key from relevant details from a Machine Readable Zone.
   *
   * @param mrz the details from the Machine Readable Zone
   *
   * @return the PACE key
   *
   * @throws GeneralSecurityException on error
   */
  public static PACEKeySpec createMRZKey(BACKeySpec mrz) throws GeneralSecurityException {
    return new PACEKeySpec(PACEProtocol.computeKeySeedForPACE(mrz), PassportService.MRZ_PACE_KEY_REFERENCE);
  }

  /**
   * Creates a PACE key from a Card Access Number.
   *
   * @param can the Card Access Number
   *
   * @return the PACE key
   */
  public static PACEKeySpec createCANKey(String can) {
    return new PACEKeySpec(can, PassportService.CAN_PACE_KEY_REFERENCE);
  }

  /**
   * Creates a PACE key from a PIN.
   *
   * @param pin the PIN
   *
   * @return the PACE key
   */
  public static PACEKeySpec createPINKey(String pin) {
    return new PACEKeySpec(pin, PassportService.PIN_PACE_KEY_REFERENCE);
  }

  /**
   * Creates a PACE key from a PUK.
   *
   * @param puk the PUK
   *
   * @return the PACE key
   */
  public static PACEKeySpec createPUKKey(String puk) {
    return new PACEKeySpec(puk, PassportService.PUK_PACE_KEY_REFERENCE);
  }

  /**
   * Returns the algorithm.
   *
   * @return the algorithm
   */
  public String getAlgorithm() {
    return "PACE";
  }

  /**
   * Returns the type of key, valid values are
   * {@code MRZ_PACE_KEY_REFERENCE}, {@code CAN_PACE_KEY_REFERENCE},
   * {@code PIN_PACE_KEY_REFERENCE}, {@code PUK_PACE_KEY_REFERENCE}.
   *
   * @return the type of key
   */
  public byte getKeyReference() {
    return keyReference;
  }

  /**
   * Returns the key bytes.
   *
   * @return the key bytes
   */
  public byte[] getKey() {
    return key;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(key);
    result = prime * result + keyReference;
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    PACEKeySpec other = (PACEKeySpec) obj;
    if (!Arrays.equals(key, other.key)) {
      return false;
    }
    if (keyReference != other.keyReference) {
      return false;
    }
    return true;
  }

  @Override
  public String toString() {
    return new StringBuilder()
        .append("PACEKeySpec [")
        .append("key: ").append(Hex.bytesToHexString(key)).append(", ")
        .append("keyReference: ").append(keyReferenceToString(keyReference))
        .append("]")
        .toString();
  }

  /**
   * Returns a textual representation of the given key reference parameter.
   *
   * @param keyReference a key reference parameter
   *
   * @return a textual representation of the key reference
   */
  private static String keyReferenceToString(byte keyReference) {
    switch (keyReference) {
      case PassportService.MRZ_PACE_KEY_REFERENCE:
        return "MRZ";
      case PassportService.CAN_PACE_KEY_REFERENCE:
        return "CAN";
      case PassportService.PIN_PACE_KEY_REFERENCE:
        return "PIN";
      case PassportService.PUK_PACE_KEY_REFERENCE:
        return "PUK";
      case PassportService.NO_PACE_KEY_REFERENCE:
        return "NO";
      default:
        return Integer.toString(keyReference);
    }
  }
}

