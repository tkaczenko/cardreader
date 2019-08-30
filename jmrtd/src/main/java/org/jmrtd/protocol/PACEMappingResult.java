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
 * $Id: PACEMappingResult.java 1764 2018-02-19 16:19:25Z martijno $
 */

package org.jmrtd.protocol;

import java.io.Serializable;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * The result of a the nonce mapping step.
 * This is the abstract super type, specific implementations
 * will contain more relevant details.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1764 $
 */
public abstract class PACEMappingResult implements Serializable {

  private static final long serialVersionUID = 2773111318950631118L;

  // FIXME: Should be serializable instead of transient.
  private transient AlgorithmParameterSpec staticParameters;

  // FIXME: Should be serializable instead of transient.
  private transient AlgorithmParameterSpec ephemeralParameters;

  private byte[] piccNonce;

  /**
   * Constructs a mapping result.
   *
   * @param staticParameters the static agreement parameters
   * @param piccNonce the nonce that was sent by the PICC
   * @param ephemeralParameters the resulting ephemeral parameters
   */
  public PACEMappingResult(AlgorithmParameterSpec staticParameters, byte[] piccNonce, AlgorithmParameterSpec ephemeralParameters) {
    this.staticParameters = staticParameters;
    this.ephemeralParameters = ephemeralParameters;

    this.piccNonce = null;
    if (piccNonce != null) {
      this.piccNonce = new byte[piccNonce.length];
      System.arraycopy(piccNonce, 0, this.piccNonce, 0, piccNonce.length);
    }
  }

  /**
   * Returns the static agreement parameters.
   *
   * @return the original parameters
   */
  public AlgorithmParameterSpec getStaticParameters() {
    return staticParameters;
  }

  /**
   * Returns the ephemeral (derived) agreement parameters.
   *
   * @return the resulting parameters
   */
  public AlgorithmParameterSpec getEphemeralParameters() {
    return ephemeralParameters;
  }

  /**
   * Returns the nonce that was sent by the PICC.
   *
   * @return the nonce
   */
  public byte[] getPICCNonce() {
    return piccNonce;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((ephemeralParameters == null) ? 0 : ephemeralParameters.hashCode());
    result = prime * result + Arrays.hashCode(piccNonce);
    result = prime * result + ((staticParameters == null) ? 0 : staticParameters.hashCode());
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

    PACEMappingResult other = (PACEMappingResult) obj;
    if (ephemeralParameters == null) {
      if (other.ephemeralParameters != null) {
        return false;
      }
    } else if (!ephemeralParameters.equals(other.ephemeralParameters)) {
      return false;
    }
    if (!Arrays.equals(piccNonce, other.piccNonce)) {
      return false;
    }
    if (staticParameters == null) {
      if (other.staticParameters != null) {
        return false;
      }
    } else if (!staticParameters.equals(other.staticParameters)) {
      return false;
    }

    return true;
  }
}
