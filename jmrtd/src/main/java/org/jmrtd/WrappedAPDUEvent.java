/*
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
 * $Id: WrappedAPDUEvent.java 1763 2018-02-18 07:41:30Z martijno $
 */

package org.jmrtd;

import java.io.Serializable;

import net.sf.scuba.smartcards.APDUEvent;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ResponseAPDU;

/**
 * An event signifying an exchange of wrapped (protected) command and response APDUs.
 * This makes the underlying unprotected APDUs available.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1763 $
 *
 * @since 0.6.4
 */
public class WrappedAPDUEvent extends APDUEvent {

  private static final long serialVersionUID = 5958662425525890224L;

  private CommandAPDU plainTextCommandAPDU;

  private ResponseAPDU plainTextResponseAPDU;

  /**
   * Creates an APDU exchange event.
   *
   * @param source the source of the event, typically a card service
   * @param type the type of event, typically this identifies the APDU wrapper somehow
   * @param sequenceNumber the sequence number of the APDU exchange within a session
   * @param plainTextCommandAPDU the unprotected command APDU
   * @param plainTextResponseAPDU the unprotected response APDU
   * @param wrappedCommandAPDU the protected command APDU
   * @param wrappedResponseAPDU the protected command APDU
   */
  public WrappedAPDUEvent(Object source, Serializable type, int sequenceNumber,
      CommandAPDU plainTextCommandAPDU, ResponseAPDU plainTextResponseAPDU,
      CommandAPDU wrappedCommandAPDU, ResponseAPDU wrappedResponseAPDU) {
    super(source, type, sequenceNumber, wrappedCommandAPDU, wrappedResponseAPDU);
    this.plainTextCommandAPDU = plainTextCommandAPDU;
    this.plainTextResponseAPDU = plainTextResponseAPDU;
  }

  /**
   * Returns the unprotected, plain-text Command APDU.
   *
   * @return the unprotected, plain-text Command APDU
   */
  public CommandAPDU getPlainTextCommandAPDU() {
    return plainTextCommandAPDU;
  }

  /**
   * Returns the unprotected, plain-text Response APDU.
   *
   * @return the unprotected, plain-text Response APDU
   */
  public ResponseAPDU getPlainTextResponseAPDU() {
    return plainTextResponseAPDU;
  }
}

