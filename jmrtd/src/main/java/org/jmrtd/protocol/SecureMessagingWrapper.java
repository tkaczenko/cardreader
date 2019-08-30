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
 * $Id: SecureMessagingWrapper.java 1807 2019-03-06 23:01:37Z martijno $
 */

package org.jmrtd.protocol;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.jmrtd.Util;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.tlv.TLVUtil;

/**
 * Secure messaging wrapper base class.
 *
 * @author The JMRTD team
 *
 * @version $Revision: 1807 $
 */
public abstract class SecureMessagingWrapper implements Serializable, APDUWrapper {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd.protocol");

  private static final long serialVersionUID = 4709645514566992414L;

  private int maxTranceiveLength;

  private boolean shouldCheckMAC;

  private long ssc;

  private transient Cipher cipher;
  private transient Mac mac;

  private SecretKey ksEnc;
  private SecretKey ksMac;

  /**
   * Constructs a secure messaging wrapper based on the secure messaging
   * session keys and the initial value of the send sequence counter.
   *
   * @param ksEnc the session key for encryption
   * @param ksMac the session key for message authenticity
   * @param cipherAlg the mnemonic Java string describing the cipher algorithm
   * @param macAlg the mnemonic Java string describing the message authenticity checking algorithm
   * @param maxTranceiveLength the maximum tranceive length, typical values are 256 or 65536
   * @param shouldCheckMAC a boolean indicating whether this wrapper will check the MAC in wrapped response APDUs
   * @param ssc the initial value of the send sequence counter
   *
   * @throws GeneralSecurityException when the available JCE providers cannot provide the necessary cryptographic primitives
   */
  protected SecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac, String cipherAlg, String macAlg, int maxTranceiveLength, boolean shouldCheckMAC, long ssc) throws GeneralSecurityException {
    this.maxTranceiveLength = maxTranceiveLength;
    this.shouldCheckMAC = shouldCheckMAC;

    this.ksEnc = ksEnc;
    this.ksMac = ksMac;
    this.ssc = ssc;

    this.cipher = Util.getCipher(cipherAlg);
    this.mac = Util.getMac(macAlg);
  }

  /**
   * Returns a copy of the given wrapper, with an identical (but perhaps independent)
   * state for known secure messaging wrapper types. If the wrapper type is not recognized
   * the original wrapper is returned.
   *
   * @param wrapper the original wrapper
   *
   * @return a copy of that wrapper
   */
  public static SecureMessagingWrapper getInstance(SecureMessagingWrapper wrapper) {
    try {
      if (wrapper instanceof DESedeSecureMessagingWrapper) {
        DESedeSecureMessagingWrapper desEDESecureMessagingWrapper = (DESedeSecureMessagingWrapper)wrapper;
        return new DESedeSecureMessagingWrapper(desEDESecureMessagingWrapper);
      } else if (wrapper instanceof AESSecureMessagingWrapper) {
        AESSecureMessagingWrapper aesSecureMessagingWrapper = (AESSecureMessagingWrapper)wrapper;
        return new AESSecureMessagingWrapper(aesSecureMessagingWrapper);
      }
    } catch (GeneralSecurityException gse) {
      LOGGER.log(Level.WARNING, "Could not copy wrapper", gse);
    }

    LOGGER.warning("Not copying wrapper");
    return wrapper;
  }

  /**
   * Returns the current value of the send sequence counter.
   *
   * @return the current value of the send sequence counter.
   */
  public long getSendSequenceCounter() {
    return ssc;
  }

  /**
   * Returns the shared key for encrypting APDU payloads.
   *
   * @return the encryption key
   */
  public SecretKey getEncryptionKey() {
    return ksEnc;
  }

  /**
   * Returns the shared key for computing message authentication codes over APDU payloads.
   *
   * @return the MAC key
   */
  public SecretKey getMACKey() {
    return ksMac;
  }

  /**
   * Returns a boolean indicating whether this wrapper will check the MAC in wrapped response APDUs.
   *
   * @return a boolean indicating whether this wrapper will check the MAC in wrapped response APDUs
   */
  public boolean shouldCheckMAC() {
    return shouldCheckMAC;
  }

  /**
   * Returns the maximum tranceive length of wrapped command and response APDUs,
   * typical values are 256 and 65536.
   *
   * @return the maximum tranceive length of wrapped command and response APDUs
   */
  public int getMaxTranceiveLength() {
    return maxTranceiveLength;
  }

  /**
   * Wraps the APDU buffer of a command APDU.
   * As a side effect, this method increments the internal send
   * sequence counter maintained by this wrapper.
   *
   * @param commandAPDU buffer containing the command APDU
   *
   * @return length of the command APDU after wrapping
   */
  public CommandAPDU wrap(CommandAPDU commandAPDU) {
    ssc++;
    try {
      return wrapCommandAPDU(commandAPDU);
    } catch (GeneralSecurityException gse) {
      throw new IllegalStateException("Unexpected exception", gse);
    } catch (IOException ioe) {
      throw new IllegalStateException("Unexpected exception", ioe);
    }
  }

  /**
   * Unwraps the APDU buffer of a response APDU.
   *
   * @param responseAPDU the response APDU
   *
   * @return a new byte array containing the unwrapped buffer
   */
  public ResponseAPDU unwrap(ResponseAPDU responseAPDU) {
    ssc++;
    try {
      byte[] data = responseAPDU.getData();
      if (data == null || data.length <= 0) {
        // no sense in unwrapping - card indicates some kind of error
        throw new IllegalStateException("Card indicates SM error, SW = " + Integer.toHexString(responseAPDU.getSW() & 0xFFFF));
        /* FIXME: wouldn't it be cleaner to throw a CardServiceException? */
      }
      return unwrapResponseAPDU(responseAPDU);
    } catch (GeneralSecurityException gse) {
      throw new IllegalStateException("Unexpected exception", gse);
    } catch (IOException ioe) {
      throw new IllegalStateException("Unexpected exception", ioe);
    }
  }

  /**
   * Checks the MAC.
   *
   * @param rapdu the bytes of the response APDU, including the {@code 0x8E} tag, the length of the MAC, the MAC itself, and the status word
   * @param cc the MAC sent by the other party
   *
   * @return whether the computed MAC is identical
   *
   * @throws GeneralSecurityException on security related error
   */
  protected boolean checkMac(byte[] rapdu, byte[] cc) throws GeneralSecurityException {
    try {
      ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
      DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
      dataOutputStream.write(getEncodedSendSequenceCounter());
      byte[] paddedData = Util.pad(rapdu, 0, rapdu.length - 2 - 8 - 2, getPadLength());
      dataOutputStream.write(paddedData, 0, paddedData.length);
      dataOutputStream.flush();
      dataOutputStream.close();
      mac.init(ksMac);
      byte[] cc2 = mac.doFinal(byteArrayOutputStream.toByteArray());

      if (cc2.length > 8 && cc.length == 8) {
        byte[] newCC2 = new byte[8];
        System.arraycopy(cc2, 0, newCC2, 0, newCC2.length);
        cc2 = newCC2;
      }

      return Arrays.equals(cc, cc2);
    } catch (IOException ioe) {
      LOGGER.log(Level.WARNING, "Exception checking MAC", ioe);
      return false;
    }
  }

  /**
   * Returns the length (in bytes) to use for padding.
   *
   * @return the length to use for padding
   */
  protected abstract int getPadLength();

  /**
   * Returns the initialization vector to be used by the encryption cipher.
   *
   * @return the initialization vector as a paramaters specification
   *
   * @throws GeneralSecurityException on error constructing the parameter specification object
   */
  protected abstract IvParameterSpec getIV() throws GeneralSecurityException;

  /**
   * Returns the send sequence counter encoded as a byte array for inclusion in wrapped APDUs.
   *
   * @return the send sequence counter encoded as byte array
   */
  protected abstract byte[] getEncodedSendSequenceCounter();

  /* PRIVATE BELOW. */

  /*
   * The SM Data Objects (see [ISO/IEC 7816-4]) MUST be used in the following order:
   *   - Command APDU: [DO‘85’ or DO‘87’] [DO‘97’] DO‘8E’.
   *   - Response APDU: [DO‘85’ or DO‘87’] [DO‘99’] DO‘8E’.
   */

  /**
   * Performs the actual encoding of a command APDU.
   * Based on Section E.3 of ICAO-TR-PKI, especially the examples.
   *
   * @param commandAPDU the command APDU
   *
   * @return a byte array containing the wrapped APDU buffer
   *
   * @throws GeneralSecurityException on error wrapping the APDU
   * @throws IOException on error writing the result to memory
   */
  private CommandAPDU wrapCommandAPDU(CommandAPDU commandAPDU) throws GeneralSecurityException, IOException {
    int cla = commandAPDU.getCLA();
    int ins = commandAPDU.getINS();
    int p1 = commandAPDU.getP1();
    int p2 = commandAPDU.getP2();
    int lc = commandAPDU.getNc();
    int le = commandAPDU.getNe();

    byte[] maskedHeader = new byte[] { (byte)(cla | (byte)0x0C), (byte)ins, (byte)p1, (byte)p2 };
    byte[] paddedMaskedHeader = Util.pad(maskedHeader, getPadLength());

    boolean hasDO85 = ((byte)commandAPDU.getINS() == ISO7816.INS_READ_BINARY2);

    byte[] do8587 = new byte[0];
    byte[] do97 = new byte[0];

    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    try {

      /* Include the expected length, if present. */
      if (le > 0) {
        do97 = TLVUtil.wrapDO(0x97, encodeLe(le));
      }

      /* Encrypt command data, if present. */
      if (lc > 0) {
        byte[] data = Util.pad(commandAPDU.getData(), getPadLength());

        /* Re-initialize cipher, this time with IV based on SSC. */
        cipher.init(Cipher.ENCRYPT_MODE, ksEnc, getIV());
        byte[] ciphertext = cipher.doFinal(data);

        byteArrayOutputStream.reset();
        byteArrayOutputStream.write(hasDO85 ? (byte)0x85 : (byte)0x87);
        byteArrayOutputStream.write(TLVUtil.getLengthAsBytes(ciphertext.length + (hasDO85 ? 0 : 1)));
        if (!hasDO85) {
          byteArrayOutputStream.write(0x01);
        }
        byteArrayOutputStream.write(ciphertext, 0, ciphertext.length);
        do8587 = byteArrayOutputStream.toByteArray();
      }

      byteArrayOutputStream.reset();
      byteArrayOutputStream.write(getEncodedSendSequenceCounter());
      byteArrayOutputStream.write(paddedMaskedHeader);
      byteArrayOutputStream.write(do8587);
      byteArrayOutputStream.write(do97);
      byte[] n = Util.pad(byteArrayOutputStream.toByteArray(), getPadLength());

      /* Compute cryptographic checksum... */
      mac.init(ksMac);
      byte[] cc = mac.doFinal(n);
      int ccLength = cc.length;
      if (ccLength != 8) {
        ccLength = 8;
      }

      byteArrayOutputStream.reset();
      byteArrayOutputStream.write((byte)0x8E);
      byteArrayOutputStream.write(ccLength);
      byteArrayOutputStream.write(cc, 0, ccLength);
      byte[] do8E = byteArrayOutputStream.toByteArray();

      /* Construct protected APDU... */
      byteArrayOutputStream.reset();
      byteArrayOutputStream.write(do8587);
      byteArrayOutputStream.write(do97);
      byteArrayOutputStream.write(do8E);

    } finally {
      try {
        byteArrayOutputStream.close();
      } catch (IOException ioe) {
        /* Never happens. */
        LOGGER.log(Level.FINE, "Error closing stream", ioe);
      }
    }

    byte[] data = byteArrayOutputStream.toByteArray();

    /*
     * The requested response is 0x00 or 0x0000, depending on whether extended length is needed.
     */
    if (le <= 256 && data.length <= 255) {
      return new CommandAPDU(maskedHeader[0], maskedHeader[1], maskedHeader[2], maskedHeader[3], data, 256);
    } else if (le > 256 || data.length > 255) {
      return new CommandAPDU(maskedHeader[0], maskedHeader[1], maskedHeader[2], maskedHeader[3], data, 65536);
    } else {
      /* Not sure if this case ever occurs, but this is consistent with previous behavior. */
      return new CommandAPDU(maskedHeader[0], maskedHeader[1], maskedHeader[2], maskedHeader[3], data, getMaxTranceiveLength());
    }
  }

  /**
   * Unwraps a response APDU sent by the ICC.
   * Based on Section E.3 of TR-PKI, especially the examples.
   *
   * @param responseAPDU the response APDU
   *
   * @return a byte array containing the unwrapped APDU buffer
   *
   * @throws GeneralSecurityException on error unwrapping the APDU
   * @throws IOException on error writing the result to memory
   */
  private ResponseAPDU unwrapResponseAPDU(ResponseAPDU responseAPDU) throws GeneralSecurityException, IOException {
    byte[] rapdu = responseAPDU.getBytes();
    if (rapdu == null || rapdu.length < 2) {
      throw new IllegalArgumentException("Invalid response APDU");
    }
    cipher.init(Cipher.DECRYPT_MODE, ksEnc, getIV());

    byte[] data = new byte[0];
    byte[] cc = null;
    short sw = 0;
    DataInputStream inputStream = new DataInputStream(new ByteArrayInputStream(rapdu));
    try {
      boolean isFinished = false;
      while (!isFinished) {
        int tag = inputStream.readByte();
        switch (tag) {
          case (byte)0x87:
            data = readDO87(inputStream, false);
            break;
          case (byte)0x85:
            data = readDO87(inputStream, true);
            break;
          case (byte)0x99:
            sw = readDO99(inputStream);
            break;
          case (byte)0x8E:
            cc = readDO8E(inputStream);
            isFinished = true;
            break;
          default:
            LOGGER.warning("Unexpected tag " + Integer.toHexString(tag));
            break;
        }
      }
    } finally {
      inputStream.close();
    }
    if (shouldCheckMAC() && !checkMac(rapdu, cc)) {
      throw new IllegalStateException("Invalid MAC");
    }
    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    bOut.write(data, 0, data.length);
    bOut.write((sw & 0xFF00) >> 8);
    bOut.write(sw & 0x00FF);
    return new ResponseAPDU(bOut.toByteArray());
  }

  /**
   * Encodes the expected length value to a byte array for inclusion in wrapped APDUs.
   * The result is a byte array of length 1 or 2.
   *
   * @param le a non-negative expected length
   *
   * @return a byte array with the encoded expected length
   */
  private byte[] encodeLe(int le) {
    if (0 <= le && le <= 256) {
      /* NOTE: Both 0x00 and 0x100 are mapped to 0x00. */
      return new byte[] { (byte)le };
    } else {
      return new byte[] { (byte)((le & 0xFF00) >> 8), (byte)(le & 0xFF) };
    }
  }

  /**
   * Reads a data object.
   * The {@code 0x87} tag has already been read.
   *
   * @param inputStream the stream to read from
   * @param do85 whether to expect a {@code 0x85} (including an extra 1 length) data object.
   *
   * @return the bytes that were read
   *
   * @throws IOException on error reading from the stream
   * @throws GeneralSecurityException on error decrypting the data
   */
  private byte[] readDO87(DataInputStream inputStream, boolean do85) throws IOException, GeneralSecurityException {
    /* Read length... */
    int length = 0;
    int buf = inputStream.readUnsignedByte();
    if ((buf & 0x00000080) != 0x00000080) {
      /* Short form */
      length = buf;
      if (!do85) {
        buf = inputStream.readUnsignedByte(); /* should be 0x01... */
        if (buf != 0x01) {
          throw new IllegalStateException("DO'87 expected 0x01 marker, found " + Integer.toHexString(buf & 0xFF));
        }
      }
    } else {
      /* Long form */
      int lengthBytesCount = buf & 0x0000007F;
      for (int i = 0; i < lengthBytesCount; i++) {
        length = (length << 8) | inputStream.readUnsignedByte();
      }
      if (!do85) {
        buf = inputStream.readUnsignedByte(); /* should be 0x01... */
        if (buf != 0x01) {
          throw new IllegalStateException("DO'87 expected 0x01 marker");
        }
      }
    }
    if (!do85) {
      length--; /* takes care of the extra 0x01 marker... */
    }
    /* Read, decrypt, unpad the data... */
    byte[] ciphertext = new byte[length];
    inputStream.readFully(ciphertext);
    byte[] paddedData = cipher.doFinal(ciphertext);
    return Util.unpad(paddedData);
  }

  /**
   * Reads a data object.
   * The {@code 0x99} tag has already been read.
   *
   * @param inputStream the stream to read from
   *
   * @return the status word
   *
   * @throws IOException on error reading from the stream
   */
  private short readDO99(DataInputStream inputStream) throws IOException {
    int length = inputStream.readUnsignedByte();
    if (length != 2) {
      throw new IllegalStateException("DO'99 wrong length");
    }
    byte sw1 = inputStream.readByte();
    byte sw2 = inputStream.readByte();
    return (short)(((sw1 & 0x000000FF) << 8) | (sw2 & 0x000000FF));
  }

  /**
   * Reads a data object.
   * This assumes that the {@code 0x8E} tag has already been read.
   *
   * @param inputStream the stream to read from
   *
   * @return the bytes that were read
   *
   * @throws IOException on error
   */
  private byte[] readDO8E(DataInputStream inputStream) throws IOException {
    int length = inputStream.readUnsignedByte();
    if (length != 8 && length != 16) {
      throw new IllegalStateException("DO'8E wrong length for MAC: " + length);
    }
    byte[] cc = new byte[length];
    inputStream.readFully(cc);
    return cc;
  }

  @Override
  public String toString() {
    return new StringBuilder()
        .append("SecureMessagingWrapper [")
        .append("ssc: ").append(ssc)
        .append(", ksEnc: ").append(ksEnc)
        .append(", ksMac: ").append(ksMac)
        .append(", maxTranceiveLength: ").append(maxTranceiveLength)
        .append(", shouldCheckMAC: ").append(shouldCheckMAC)
        .append("]")
        .toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((ksEnc == null) ? 0 : ksEnc.hashCode());
    result = prime * result + ((ksMac == null) ? 0 : ksMac.hashCode());
    result = prime * result + maxTranceiveLength;
    result = prime * result + (shouldCheckMAC ? 1231 : 1237);
    result = prime * result + (int) (ssc ^ (ssc >>> 32));
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

    SecureMessagingWrapper other = (SecureMessagingWrapper) obj;
    if (ksEnc == null) {
      if (other.ksEnc != null) {
        return false;
      }
    } else if (!ksEnc.equals(other.ksEnc)) {
      return false;
    }
    if (ksMac == null) {
      if (other.ksMac != null) {
        return false;
      }
    } else if (!ksMac.equals(other.ksMac)) {
      return false;
    }
    if (maxTranceiveLength != other.maxTranceiveLength) {
      return false;
    }
    if (shouldCheckMAC != other.shouldCheckMAC) {
      return false;
    }

    return ssc == other.ssc;
  }
}
