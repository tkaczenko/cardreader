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
 * $Id: AESSecureMessagingWrapper.java 1805 2018-11-26 21:39:46Z martijno $
 */

package org.jmrtd.protocol;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.jmrtd.Util;

/**
 * An AES secure messaging wrapper for APDUs. Based on TR-SAC.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1805 $
 */
public class AESSecureMessagingWrapper extends SecureMessagingWrapper implements Serializable {

  private static final long serialVersionUID = 2086301081448345496L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private transient Cipher sscIVCipher;

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
  public AESSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac, long ssc) throws GeneralSecurityException {
    this(ksEnc, ksMac, 256, true, ssc);
  }

  /**
   * Constructs a secure messaging wrapper based on the given existing secure messaging wrapper.
   * This is a convenience copy constructor.

   * @param wrapper an existing wrapper
   *
   * @throws GeneralSecurityException when the available JCE providers cannot provide the necessary cryptographic primitives
   */
  public AESSecureMessagingWrapper(AESSecureMessagingWrapper wrapper) throws GeneralSecurityException {
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
  public AESSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac, int maxTranceiveLength, boolean shouldCheckMAC, long ssc) throws GeneralSecurityException {
    super(ksEnc, ksMac, "AES/CBC/NoPadding", "AESCMAC", maxTranceiveLength, shouldCheckMAC, ssc);
    sscIVCipher = Util.getCipher("AES/ECB/NoPadding", Cipher.ENCRYPT_MODE, ksEnc);
  }

  /**
   * Returns the type of secure messaging wrapper (in this case {@code "AES"}).
   *
   * @return the type of secure messaging wrapper
   */
  public String getType() {
    return "AES";
  }

  /**
   * Returns the length (in bytes) to use for padding.
   * For AES this is 16.
   *
   * @return the length to use for padding
   */
  @Override
  public int getPadLength() {
    return 16;
  }

  /**
   * Returns the send sequence counter as bytes, making sure
   * the 128 bit (16 byte) block-size is used.
   *
   * @return the send sequence counter as a 16 byte array
   */
  @Override
  public byte[] getEncodedSendSequenceCounter() {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(16);
    try {
      byteArrayOutputStream.write(0x00);
      byteArrayOutputStream.write(0x00);
      byteArrayOutputStream.write(0x00);
      byteArrayOutputStream.write(0x00);
      byteArrayOutputStream.write(0x00);
      byteArrayOutputStream.write(0x00);
      byteArrayOutputStream.write(0x00);
      byteArrayOutputStream.write(0x00);

      /* A long will take 8 bytes. */
      DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
      dataOutputStream.writeLong(getSendSequenceCounter());
      dataOutputStream.close();
      return byteArrayOutputStream.toByteArray();
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
    return null;
  }

  @Override
  public String toString() {
    return new StringBuilder()
        .append("AESSecureMessagingWrapper [")
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
    return 71 * super.hashCode() + 17;
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

  /**
   * Returns the IV by encrypting the send sequence counter.
   *
   * AES uses IV = E K_Enc , SSC), see ICAO SAC TR Section 4.6.3.
   *
   * @return the initialization vector specification
   *
   * @throws GeneralSecurityException on error
   */
  @Override
  protected IvParameterSpec getIV() throws GeneralSecurityException {
    byte[] encryptedSSC = sscIVCipher.doFinal(getEncodedSendSequenceCounter());
    return new IvParameterSpec(encryptedSSC);
  }
}
