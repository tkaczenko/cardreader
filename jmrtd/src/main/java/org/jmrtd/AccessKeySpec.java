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
 * $Id: AccessKeySpec.java 1799 2018-10-30 16:25:48Z martijno $
 */

package org.jmrtd;

import java.io.Serializable;
import java.security.spec.KeySpec;

/**
 * Super interface for BACKeySpec and PACEKeySpec.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1799 $
 */
public interface AccessKeySpec extends Serializable, KeySpec {

  /**
   * Returns the type of access key.
   * Typical values are {@code "BAC"}, and {@code "PACE"}.
   *
   * @return the type of access key
   */
  String getAlgorithm();

  /**
   * Returns the bytes used for deriving the key seed.
   *
   * @return a byte array with the input for key derivation
   */
  byte[] getKey();
}
