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
 * $Id: PACEAPDUSender.java 1817 2019-08-02 12:09:17Z martijno $
 */

package org.jmrtd.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.APDULevelPACECapable;
import org.jmrtd.AccessDeniedException;
import org.jmrtd.Util;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.tlv.TLVUtil;

/**
 * A low-level APDU sender to support the PACE protocol.
 *
 * @author The JMRTD team
 *
 * @version $Revision: 1817 $
 *
 * @since 0.7.0
 */
public class PACEAPDUSender implements APDULevelPACECapable {

  /** Shared secret type for non-PACE key. */
  public static final byte NO_PACE_KEY_REFERENCE = 0x00;

  /** Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1. */
  public static final byte MRZ_PACE_KEY_REFERENCE = 0x01;

  /** Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1. */
  public static final byte CAN_PACE_KEY_REFERENCE = 0x02;

  /** Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1. */
  public static final byte PIN_PACE_KEY_REFERENCE = 0x03;

  /** Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1. */
  public static final byte PUK_PACE_KEY_REFERENCE = 0x04;

  /** The general Authenticate command is used to perform the PACE protocol. See Section 3.2.2 of SAC-TR 1.01. */
  private static final byte INS_PACE_GENERAL_AUTHENTICATE = (byte)0x86;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd.protocol");

  private SecureMessagingAPDUSender secureMessagingSender;

  /**
   * Creates an APDU sender to support the PACE protocol.
   *
   * @param service the card service to tranceive APDUs
   */
  public PACEAPDUSender(CardService service) {
    this.secureMessagingSender = new SecureMessagingAPDUSender(service);
  }

  /**
   * The MSE AT APDU for PACE, see ICAO TR-SAC-1.01, Section 3.2.1, BSI TR 03110 v2.03 B11.1.
   * Note that (for now) caller is responsible for prefixing the byte[] params with specified tags.
   *
   * @param wrapper secure messaging wrapper
   * @param oid OID of the protocol to select (this method will prefix {@code 0x80})
   * @param refPublicKeyOrSecretKey value specifying whether to use MRZ ({@code 0x01}) or CAN ({@code 0x02}) (this method will prefix {@code 0x83})
   * @param refPrivateKeyOrForComputingSessionKey indicates a private key or reference for computing a session key (this method will prefix {@code 0x84})
   *
   * @throws CardServiceException on error
   */
  public synchronized void sendMSESetATMutualAuth(APDUWrapper wrapper, String oid,
      int refPublicKeyOrSecretKey, byte[] refPrivateKeyOrForComputingSessionKey) throws CardServiceException {

    if (oid == null) {
      throw new IllegalArgumentException("OID cannot be null");
    }

    byte[] oidBytes = Util.toOIDBytes(oid);

    /*
     * 0x83 Reference of a public key / secret key.
     * The password to be used is indicated as follows: 0x01: MRZ, 0x02: CAN.
     */
    if (!(refPublicKeyOrSecretKey == MRZ_PACE_KEY_REFERENCE
        || refPublicKeyOrSecretKey == CAN_PACE_KEY_REFERENCE
        || refPublicKeyOrSecretKey == PIN_PACE_KEY_REFERENCE
        || refPublicKeyOrSecretKey == PUK_PACE_KEY_REFERENCE)) {
      throw new IllegalArgumentException("Unsupported key type reference (MRZ, CAN, etc), found " + refPublicKeyOrSecretKey);
    }

    byte[] refPublicKeyOrSecretKeyBytes = TLVUtil.wrapDO(0x83, new byte[] { (byte)refPublicKeyOrSecretKey }); /* FIXME: define constant for 0x83 */

    /*
     * 0x84 Reference of a private key / Reference for computing a
     * session key.
     * This data object is REQUIRED to indicate the identifier
     * of the domain parameters to be used if the domain
     * parameters are ambiguous, i.e. more than one set of
     * domain parameters is available for PACE.
     */
    if (refPrivateKeyOrForComputingSessionKey != null) {
      refPrivateKeyOrForComputingSessionKey = TLVUtil.wrapDO(0x84, refPrivateKeyOrForComputingSessionKey);
    }

    /* Construct data. */
    ByteArrayOutputStream dataOutputStream = new ByteArrayOutputStream();
    try {
      dataOutputStream.write(oidBytes);
      dataOutputStream.write(refPublicKeyOrSecretKeyBytes);
      if (refPrivateKeyOrForComputingSessionKey != null) {
        dataOutputStream.write(refPrivateKeyOrForComputingSessionKey);
      }
    } catch (IOException ioe) {
      /* NOTE: should never happen. */
      LOGGER.log(Level.WARNING, "Error while copying data", ioe);
      throw new IllegalStateException("Error while copying data");
    }
    byte[] data = dataOutputStream.toByteArray();

    /* Tranceive APDU. */
    CommandAPDU capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_MSE, 0xC1, 0xA4, data);
    ResponseAPDU rapdu = secureMessagingSender.transmit(wrapper, capdu);

    /* Handle error status word. */
    short sw = (short)rapdu.getSW();
    if (sw != ISO7816.SW_NO_ERROR) {
      throw new CardServiceException("Sending MSE AT failed", sw);
    }
  }

  /**
   * Sends a General Authenticate command.
   *
   * @param wrapper secure messaging wrapper
   * @param data data to be sent, without the {@code 0x7C} prefix (this method will add it)
   * @param isLast indicates whether this is the last command in the chain
   *
   * @return dynamic authentication data without the {@code 0x7C} prefix (this method will remove it)
   *
   * @throws CardServiceException on error
   */
  public synchronized byte[] sendGeneralAuthenticate(APDUWrapper wrapper, byte[] data, int le, boolean isLast) throws CardServiceException {
    /* Tranceive APDU. */
    byte[] commandData = TLVUtil.wrapDO(0x7C, data); // FIXME: constant for 0x7C
    CommandAPDU capdu = new CommandAPDU(isLast ? ISO7816.CLA_ISO7816 : ISO7816.CLA_COMMAND_CHAINING, INS_PACE_GENERAL_AUTHENTICATE, 0x00, 0x00, commandData, le);
    ResponseAPDU rapdu = secureMessagingSender.transmit(wrapper, capdu);

    /* Handle error status word. */
    short sw = (short)rapdu.getSW();
    if (sw != ISO7816.SW_NO_ERROR) {
      /* If PACE fails at this stage, blame it on the PACE credentials. */
      throw new AccessDeniedException("Sending general authenticate failed", sw);
    }
    byte[] responseData = rapdu.getData();
    responseData = TLVUtil.unwrapDO(0x7C, responseData);
    return responseData;
  }
}
