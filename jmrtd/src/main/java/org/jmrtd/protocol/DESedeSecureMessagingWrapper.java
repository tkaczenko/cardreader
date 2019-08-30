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
 * $Id: DESedeSecureMessagingWrapper.java 1805 2018-11-26 21:39:46Z martijno $
 */

package org.jmrtd.protocol;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Secure messaging wrapper for APDUs.
 * Initially based on Section E.3 of ICAO-TR-PKI.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1805 $
 */
public class DESedeSecureMessagingWrapper extends SecureMessagingWrapper implements Serializable {

  private static final long serialVersionUID = -2859033943345961793L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /** Initialization vector consisting of 8 zero bytes. */
  public static final IvParameterSpec ZERO_IV_PARAM_SPEC = new IvParameterSpec(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });

  /**
   * Constructs a secure messaging wrapper based on the secure messaging
   * session keys. The initial value of the send sequence counter is set to
   * <code>0L</code>.
   *
   * @param ksEnc the session key for encryption
   * @param ksMac the session key for macs
   *
   * @throws GeneralSecurityException
   *             when the available JCE providers cannot provide the necessary
   *             cryptographic primitives
   *             ({@code "DESede/CBC/Nopadding"} Cipher, {@code "ISO9797Alg3Mac"} Mac).
   */
  public DESedeSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac) throws GeneralSecurityException {
    this(ksEnc, ksMac, true);
  }

  /**
   * Constructs a secure messaging wrapper based on the secure messaging
   * session keys. The initial value of the send sequence counter is set to
   * {@code 0L}.
   *
   * @param ksEnc the session key for encryption
   * @param ksMac the session key for macs
   * @param shouldCheckMAC a boolean indicating whether this wrapper will check the MAC in wrapped response APDUs
   *
   * @throws GeneralSecurityException
   *             when the available JCE providers cannot provide the necessary
   *             cryptographic primitives
   *             ({@code "DESede/CBC/Nopadding"} Cipher, {@code "ISO9797Alg3Mac"} Mac).
   */
  public DESedeSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac, boolean shouldCheckMAC) throws GeneralSecurityException {
    this(ksEnc, ksMac, 256, shouldCheckMAC, 0L);
  }

  /**
   * Constructs a secure messaging wrapper based on the secure messaging
   * session keys and the initial value of the send sequence counter.
   * Used in BAC and EAC 1.
   *
   * @param ksEnc the session key for encryption
   * @param ksMac the session key for macs
   * @param ssc the initial value of the send sequence counter
   *
   * @throws GeneralSecurityException when the available JCE providers cannot provide the necessary cryptographic primitives
   */
  public DESedeSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac, long ssc) throws GeneralSecurityException {
    this(ksEnc, ksMac, 256, true, ssc);
  }

  /**
   * Constructs a secure messaging wrapper based on the given existing secure messaging wrapper.
   * This is a convenience copy constructor.

   * @param wrapper an existing wrapper
   *
   * @throws GeneralSecurityException when the available JCE providers cannot provide the necessary cryptographic primitives
   */
  public DESedeSecureMessagingWrapper(DESedeSecureMessagingWrapper wrapper) throws GeneralSecurityException {
    this(wrapper.getEncryptionKey(), wrapper.getMACKey(), wrapper.getMaxTranceiveLength(), wrapper.shouldCheckMAC(), wrapper.getSendSequenceCounter());
  }

  /**
   * Constructs a secure messaging wrapper based on the secure messaging
   * session keys and the initial value of the send sequence counter.
   * Used in BAC and EAC 1.
   *
   * @param ksEnc the session key for encryption
   * @param ksMac the session key for macs
   * @param maxTranceiveLength the maximum tranceive length, typical values are 256 or 65536
   * @param shouldCheckMAC a boolean indicating whether this wrapper will check the MAC in wrapped response APDUs
   * @param ssc the initial value of the send sequence counter
   *
   * @throws GeneralSecurityException when the available JCE providers cannot provide the necessary cryptographic primitives
   */
  public DESedeSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac, int maxTranceiveLength, boolean shouldCheckMAC, long ssc) throws GeneralSecurityException {
    super(ksEnc, ksMac, "DESede/CBC/NoPadding", "ISO9797Alg3Mac", maxTranceiveLength, shouldCheckMAC, ssc);
  }

  /**
   * Returns the type of secure messaging wrapper.
   * In this case {@code "DESede"} will be returned.
   *
   * @return the type of secure messaging wrapper
   */
  public String getType() {
    return "DESede";
  }

  /**
   * Returns the length (in bytes) to use for padding.
   * For 3DES this is 8.
   *
   * @return the length to use for padding
   */
  @Override
  public int getPadLength() {
    return 8;
  }

  @Override
  public byte[] getEncodedSendSequenceCounter() {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    try {
      DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
      dataOutputStream.writeLong(getSendSequenceCounter());
    } catch (IOException ioe) {
      /* Never happens. */
      LOGGER.log(Level.FINE, "Error writing to stream", ioe);
    } finally {
      try {
        byteArrayOutputStream.close();
      } catch (IOException ioe) {
        LOGGER.log(Level.FINE, "Error closing stream", ioe);
      }
    }

    return byteArrayOutputStream.toByteArray();
  }

  @Override
  public String toString() {
    return new StringBuilder()
        .append("DESedeSecureMessagingWrapper [")
        .append("ssc: ").append(getSendSequenceCounter())
        .append(", kEnc: ").append(getEncryptionKey())
        .append(", kMac: ").append(getMACKey())
        .append(", shouldCheckMAC: ").append(shouldCheckMAC())
        .append(", maxTranceiveLength: ").append(getMaxTranceiveLength())
        .append("]")
        .toString();
  }

  @Override
  public int hashCode() {
    return 31 * super.hashCode() + 13;
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

    return super.equals(obj);
  }

  @Override
  protected IvParameterSpec getIV() {
    return ZERO_IV_PARAM_SPEC;
  }
}
