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
 * $Id: PACEException.java 1762 2018-02-18 07:36:14Z martijno $
 */

package org.jmrtd;

import net.sf.scuba.smartcards.CardServiceException;

/**
 * An exception to signal errors during execution of the PACE protocol.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1762 $
 */
public class PACEException extends CardServiceException {

  private static final long serialVersionUID = 8383980807753919040L;

  /**
   * Creates a {@code PACEException}.
   *
   * @param msg a message
   */
  public PACEException(String msg) {
    super(msg);
  }

  /**
   * Creates a {@code PACEException}.
   *
   * @param msg a message
   * @param cause the exception causing this exception
   */
  public PACEException(String msg, Throwable cause) {
    super(msg, cause);
  }

  /**
   * Creates a PACEException with a specific status word.
   *
   * @param msg a message
   * @param sw the status word that caused this CardServiceException
   */
  public PACEException(String msg, int sw) {
    super(msg, sw);
  }

  /**
   * Creates a PACEException with a specific status word.
   *
   * @param msg a message
   * @param cause the exception causing this exception
   * @param sw the status word that caused this CardServiceException
   */
  public PACEException(String msg, Throwable cause, int sw) {
    super(msg, cause, sw);
  }
}
