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
 * $Id: EACTAAPDUSender.java 1799 2018-10-30 16:25:48Z martijno $
 */

package org.jmrtd.protocol;

import org.jmrtd.APDULevelEACTACapable;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;

/**
 * A low-level APDU sender to support the (EAC) Terminal Authentication protocol.
 *
 * @author The JMRTD team
 *
 * @version $Revision: 1799 $
 *
 * @since 0.7.0
 */
public class EACTAAPDUSender implements APDULevelEACTACapable {

  private SecureMessagingAPDUSender secureMessagingSender;

  /**
   * Creates an APDU sender.
   *
   * @param service the card service for tranceiving APDUs
   */
  public EACTAAPDUSender(CardService service) {
    this.secureMessagingSender = new SecureMessagingAPDUSender(service);
  }

  /**
   * The MSE DST APDU, see EAC 1.11 spec, Section B.2.
   * This means that a case 3 APDU is sent, to which no response is expected.
   *
   * @param wrapper secure messaging wrapper
   * @param data public key reference data object (tag 0x83)
   *
   * @throws CardServiceException on error
   */
  public synchronized void sendMSESetDST(APDUWrapper wrapper, byte[] data) throws CardServiceException {
    CommandAPDU capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_MSE, 0x81, 0xB6, data);
    ResponseAPDU rapdu = secureMessagingSender.transmit(wrapper, capdu);
    short sw = (short)rapdu.getSW();
    if (sw != ISO7816.SW_NO_ERROR) {
      throw new CardServiceException("Sending MSE Set DST failed", sw);
    }
  }

  /**
   * Sends a perform security operation command in extended length mode.
   *
   * @param wrapper secure messaging wrapper
   * @param certBodyData the certificate body
   * @param certSignatureData signature data
   *
   * @throws CardServiceException on error communicating over the service
   */
  public synchronized void sendPSOExtendedLengthMode(APDUWrapper wrapper, byte[] certBodyData, byte[] certSignatureData)
      throws CardServiceException {
    byte[] certData = new byte[certBodyData.length + certSignatureData.length];
    System.arraycopy(certBodyData, 0, certData, 0, certBodyData.length);
    System.arraycopy(certSignatureData, 0, certData, certBodyData.length, certSignatureData.length);

    CommandAPDU capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_PSO, 0, 0xBE, certData);
    ResponseAPDU rapdu = secureMessagingSender.transmit(wrapper, capdu);
    short sw = (short)rapdu.getSW();
    if (sw != ISO7816.SW_NO_ERROR) {
      throw new CardServiceException("Sending PSO failed", sw);
    }
  }

  /**
   * The MSE Set AT APDU for TA, see EAC 1.11 spec, Section B.2.
   * MANAGE SECURITY ENVIRONMENT command with SET Authentication Template function.
   *
   * Note that caller is responsible for prefixing the byte[] params with specified tags.
   *
   * @param wrapper secure messaging wrapper
   * @param data public key reference data object (should already be prefixed with tag 0x83)
   *
   * @throws CardServiceException on error
   */
  public synchronized void sendMSESetATExtAuth(APDUWrapper wrapper, byte[] data) throws CardServiceException {
    CommandAPDU capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_MSE, 0x81, 0xA4, data);
    ResponseAPDU rapdu = secureMessagingSender.transmit(wrapper, capdu);
    short sw = (short)rapdu.getSW();
    if (sw != ISO7816.SW_NO_ERROR) {
      throw new CardServiceException("Sending MSE AT failed", sw);
    }
  }

  /**
   * Sends a {@code GET CHALLENGE} command to the passport.
   *
   * @param wrapper secure messaging wrapper
   *
   * @return a byte array of length 8 containing the challenge
   *
   * @throws CardServiceException on tranceive error
   */
  public synchronized byte[] sendGetChallenge(APDUWrapper wrapper) throws CardServiceException {
    CommandAPDU capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_GET_CHALLENGE, 0x00, 0x00, 8);
    ResponseAPDU rapdu = secureMessagingSender.transmit(wrapper, capdu);
    return rapdu.getData();
  }

  /**
   * Sends the EXTERNAL AUTHENTICATE command.
   * This is used in EAC-TA.
   *
   * @param wrapper secure messaging wrapper
   * @param signature terminal signature
   *
   * @throws CardServiceException if the resulting status word different from 9000
   */
  public synchronized void sendMutualAuthenticate(APDUWrapper wrapper, byte[] signature) throws CardServiceException {
    CommandAPDU capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_EXTERNAL_AUTHENTICATE, 0, 0, signature);
    ResponseAPDU rapdu = secureMessagingSender.transmit(wrapper, capdu);
    short sw = (short)rapdu.getSW();
    if (sw != ISO7816.SW_NO_ERROR) {
      throw new CardServiceException("Sending External Authenticate failed.", sw);
    }
  }
}
