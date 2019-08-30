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
 * $Id: PACESecretKeySpec.java 1786 2018-07-08 21:06:32Z martijno $
 */

package org.jmrtd;

import javax.crypto.spec.SecretKeySpec;

/**
 * A secret key for PACE.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1786 $
 *
 * (Contributions by g.giorkhelidze.)
 */
public class PACESecretKeySpec extends SecretKeySpec implements AccessKeySpec {

  private static final long serialVersionUID = -5181060361947453857L;

  private byte keyReference;

  /**
   * Constructs a secret key from the given byte array, using the first {@code len}
   * bytes of {@code key}, starting at {@code offset} inclusive.
   *
   * @param key the key bytes
   * @param offset the offset with {@code key}
   * @param len the length of the key within {@code key}
   * @param algorithm the name of the secret-key algorithm to be associated with the given key material
   * @param paceKeyReference a reference specifying the type of key from BSI TR-03110 (Appendix B)
   */
  public PACESecretKeySpec(byte[] key, int offset, int len, String algorithm, byte paceKeyReference) {
    super(key, offset, len, algorithm);
    this.keyReference = paceKeyReference;
  }

  /**
   * Constructs a secret key from the given byte array.
   *
   * @param key the key bytes
   * @param algorithm the name of the secret-key algorithm to be associated with the given key material
   * @param paceKeyReference a reference specifying the type of key from BSI TR-03110 (Appendix B)
   */
  public PACESecretKeySpec(byte[] key, String algorithm, byte paceKeyReference) {
    super(key, algorithm);
    this.keyReference = paceKeyReference;
  }

  /**
   * Returns reference specifying the type of key from BSI TR-03110 (Appendix B).
   *
   * @return a key reference
   */
  public byte getKeyReference() {
    return keyReference;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + keyReference;
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

    PACESecretKeySpec other = (PACESecretKeySpec)obj;
    return keyReference == other.keyReference;
  }

  /**
   * Returns the encoded key (key seed) used in key derivation.
   *
   * @return the encoded key
   */
  public byte[] getKey() {
    return super.getEncoded();
  }
}
