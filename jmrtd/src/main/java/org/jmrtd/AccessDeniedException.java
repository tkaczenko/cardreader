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
 * $Id: AccessDeniedException.java 1799 2018-10-30 16:25:48Z martijno $
 */

package org.jmrtd;

import net.sf.scuba.smartcards.CardServiceException;

/**
 * Exception for signaling failed BAC.
 *
 * @author The JMRTD team
 *
 * @version $Revision: 1799 $
 *
 * @since 0.7.0
 */
public class AccessDeniedException extends CardServiceException {

  private static final long serialVersionUID = -7094953658210693249L;

  private final AccessKeySpec bacKey;

  /**
   * Creates an exception.
   *
   * @param msg the message
   * @param sw status word or <code>-1</code>
   */
  public AccessDeniedException(String msg, int sw) {
    this(msg, null, sw);
  }

  /**
   * Creates an exception.
   *
   * @param msg the message
   * @param bacKey the BAC entry that was tried, or {@code null}
   * @param sw status word or {@code -1}
   */
  public AccessDeniedException(String msg, AccessKeySpec bacKey, int sw) {
    super(msg, sw);
    this.bacKey = bacKey;
  }

  /**
   * Returns the BAC key that was tried before BAC failed.
   *
   * @return a BAC key
   */
  public AccessKeySpec getAccessKey() {
    return bacKey;
  }
}
