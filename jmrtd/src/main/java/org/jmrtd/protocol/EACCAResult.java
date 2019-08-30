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
 * $Id: EACCAResult.java 1799 2018-10-30 16:25:48Z martijno $
 */

package org.jmrtd.protocol;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import org.jmrtd.Util;

import net.sf.scuba.util.Hex;

/**
 * Result of EAC Chip Authentication protocol.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1799 $
 */
public class EACCAResult implements Serializable {

  private static final long serialVersionUID = 4431711176589761513L;

  private BigInteger keyId;
  private PublicKey piccPublicKey;
  private SecureMessagingWrapper wrapper;
  private byte[] keyHash;
  private PublicKey pcdPublicKey;
  private PrivateKey pcdPrivateKey;

  /**
   * Creates a result.
   *
   * @param keyId the key identifier of the ICC's public key or {@code null}
   * @param piccPublicKey the ICC's public key
   * @param keyHash the hash of the PCD's public key
   * @param pcdPublicKey the public key of the terminal
   * @param pcdPrivateKey the private key of the terminal
   * @param wrapper secure messaging wrapper
   */
  public EACCAResult(BigInteger keyId, PublicKey piccPublicKey, byte[] keyHash, PublicKey pcdPublicKey, PrivateKey pcdPrivateKey, SecureMessagingWrapper wrapper) {
    this.keyId = keyId;
    this.piccPublicKey = piccPublicKey;
    this.keyHash = keyHash;
    this.pcdPublicKey = pcdPublicKey;
    this.pcdPrivateKey = pcdPrivateKey;
    this.wrapper = wrapper;
  }

  /**
   * Returns the ICC's public key identifier.
   *
   * @return the key id or -1
   */
  public BigInteger getKeyId() {
    return keyId;
  }

  /**
   * Returns the PICC's public key that was used as input to chip authentication protocol.
   *
   * @return the public key
   */
  public PublicKey getPublicKey() {
    return piccPublicKey;
  }

  /**
   * Returns the resulting secure messaging wrapper.
   *
   * @return the secure messaging wrapper
   */
  public SecureMessagingWrapper getWrapper() {
    return wrapper;
  }

  @Override
  public String toString() {
    return new StringBuilder()
        .append("CAResult [keyId: ").append(keyId)
        .append(", PICC public key: ").append(piccPublicKey)
        .append(", wrapper: ").append(wrapper)
        .append(", key hash: ").append(Hex.bytesToHexString(keyHash))
        .append(", PCD public key: ").append(Util.getDetailedPublicKeyAlgorithm(pcdPublicKey))
        .append(", PCD private key: ").append(Util.getDetailedPrivateKeyAlgorithm(pcdPrivateKey))
        .append("]").toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(keyHash);
    result = prime * result + ((keyId == null) ? 0 : keyId.hashCode());
    result = prime * result + ((piccPublicKey == null) ? 0 : piccPublicKey.hashCode());
    result = prime * result + ((pcdPublicKey == null) ? 0 : pcdPublicKey.hashCode());
    result = prime * result + ((pcdPrivateKey == null) ? 0 : pcdPrivateKey.hashCode());
    result = prime * result + ((wrapper == null) ? 0 : wrapper.hashCode());
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
    EACCAResult other = (EACCAResult) obj;
    if (!Arrays.equals(keyHash, other.keyHash)) {
      return false;
    }
    if (keyId == null) {
      if (other.keyId != null) {
        return false;
      }
    } else if (!keyId.equals(other.keyId)) {
      return false;
    }
    if (pcdPrivateKey == null) {
      if (other.pcdPrivateKey != null) {
        return false;
      }
    } else if (!pcdPrivateKey.equals(other.pcdPrivateKey)) {
      return false;
    }
    if (pcdPublicKey == null) {
      if (other.pcdPublicKey != null) {
        return false;
      }
    } else if (!pcdPublicKey.equals(other.pcdPublicKey)) {
      return false;
    }
    if (piccPublicKey == null) {
      if (other.piccPublicKey != null) {
        return false;
      }
    } else if (!piccPublicKey.equals(other.piccPublicKey)) {
      return false;
    }
    if (wrapper == null) {
      if (other.wrapper != null) {
        return false;
      }
    } else if (!wrapper.equals(other.wrapper)) {
      return false;
    }

    return true;
  }

  /**
   * Returns the hash of the ephemeral public key of the terminal.
   *
   * @return the hash of the ephemeral public key of the terminal
   */
  public byte[] getKeyHash() {
    return keyHash;
  }

  /**
   * Returns the ephemeral public key of the terminal that was used in the key exchange.
   *
   * @return the public key
   */
  public PublicKey getPCDPublicKey() {
    return pcdPublicKey;
  }

  /**
   * The ephemeral private key of the terminal that was used in the key exchange.
   *
   * @return the private key
   */
  public PrivateKey getPCDPrivateKey() {
    return pcdPrivateKey;
  }
}
