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
 * $Id: BACResult.java 1781 2018-05-25 11:41:48Z martijno $
 */

package org.jmrtd.protocol;

import java.io.Serializable;

import org.jmrtd.AccessKeySpec;

/**
 * Result of a Basic Access Control protocol run.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1781 $
 */
public class BACResult implements Serializable {

  private static final long serialVersionUID = -7114911372181772099L;

  private AccessKeySpec bacKey;
  private SecureMessagingWrapper wrapper;

  /**
   * Creates a BAC result without specifying the initial access key.
   *
   * @param wrapper the secure messaging wrapper that resulted from the BAC protocol run
   */
  public BACResult(SecureMessagingWrapper wrapper) {
    this(null, wrapper);
  }

  /**
   * Creates a BAC result.
   *
   * @param bacKey the initial access key
   * @param wrapper the secure messaging wrapper that resulted from the BAC protocol run
   */
  public BACResult(AccessKeySpec bacKey, SecureMessagingWrapper wrapper) {
    this.bacKey = bacKey;
    this.wrapper = wrapper;
  }

  /**
   * Returns the initial access key or {@code null}.
   *
   * @return the initial access key or {@code null}
   */
  public AccessKeySpec getBACKey() {
    return bacKey;
  }

  /**
   * Returns the secure messaging wrapper.
   *
   * @return the secure messaging wrapper
   */
  public SecureMessagingWrapper getWrapper() {
    return wrapper;
  }

  /**
   * Returns a textual representation of this terminal authentication result.
   *
   * @return a textual representation of this terminal authentication result
   */
  @Override
  public String toString() {
    return new StringBuilder()
        .append("BACResult [bacKey: " + (bacKey == null ? "-" : bacKey))
        .append(", wrapper: " + wrapper)
        .append("]")
        .toString();
  }

  @Override
  public int hashCode() {
    final int prime = 1234567891;
    int result = 1991;
    result = prime * result + ((bacKey == null) ? 0 : bacKey.hashCode());
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

    BACResult other = (BACResult) obj;
    if (bacKey == null) {
      if (other.bacKey != null) {
        return false;
      }
    } else if (!bacKey.equals(other.bacKey)) {
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
}
