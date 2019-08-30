package org.jmrtd.protocol;

import java.security.GeneralSecurityException;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.jmrtd.APDULevelBACCapable;
import org.jmrtd.AccessDeniedException;
import org.jmrtd.Util;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;

/**
 * A low-level APDU sender to support the BAC protocol.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1799 $
 *
 * @since 0.7.0
 */
public class BACAPDUSender implements APDULevelBACCapable {

  private static final Provider BC_PROVIDER = Util.getBouncyCastleProvider();

  /** Initialization vector used by the cipher below. */
  private static final IvParameterSpec ZERO_IV_PARAM_SPEC = new IvParameterSpec(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });

  private CardService service;

  /** DESede encryption/decryption cipher. */
  private Cipher cipher;

  /** ISO9797Alg3Mac. */
  private Mac mac;

  /**
   * Creates an APDU sender for tranceiving BAC protocol APDUs.
   *
   * @param service the card service for tranceiving APDUs
   */
  public BACAPDUSender(CardService service) {
    this.service = service;

    try {
      this.mac = Mac.getInstance("ISO9797Alg3Mac", BC_PROVIDER);
      this.cipher = Util.getCipher("DESede/CBC/NoPadding");
    } catch (GeneralSecurityException gse) {
      throw new IllegalStateException("Unexpected security exception during initialization", gse);
    }
  }

  /**
   * Sends a {@code GET CHALLENGE} command to the passport.
   *
   * @return a byte array of length 8 containing the challenge
   *
   * @throws CardServiceException on tranceive error
   */
  public synchronized byte[] sendGetChallenge() throws CardServiceException {
    return sendGetChallenge(null);
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
    ResponseAPDU rapdu = service.transmit(capdu);
    return rapdu.getData();
  }

  /**
   * Sends an {@code EXTERNAL AUTHENTICATE} command to the passport.
   * This is part of BAC.
   * The resulting byte array has length 32 and contains {@code rndICC}
   * (first 8 bytes), {@code rndIFD} (next 8 bytes), their key material
   * {@code kICC} (last 16 bytes).
   *
   * @param rndIFD our challenge
   * @param rndICC their challenge
   * @param kIFD our key material
   * @param kEnc the static encryption key
   * @param kMac the static mac key
   *
   * @return a byte array of length 32 containing the response that was sent
   *         by the passport, decrypted (using {@code kEnc}) and verified
   *         (using {@code kMac})
   *
   * @throws CardServiceException on tranceive error
   */
  public synchronized byte[] sendMutualAuth(byte[] rndIFD, byte[] rndICC, byte[] kIFD, SecretKey kEnc, SecretKey kMac) throws CardServiceException {
    try {
      if (rndIFD == null || rndIFD.length != 8) {
        throw new IllegalArgumentException("rndIFD wrong length");
      }
      if (rndICC == null || rndICC.length != 8) {
        rndICC = new byte[8];
      }
      if (kIFD == null || kIFD.length != 16) {
        throw new IllegalArgumentException("kIFD wrong length");
      }
      if (kEnc == null) {
        throw new IllegalArgumentException("kEnc == null");
      }
      if (kMac == null) {
        throw new IllegalArgumentException("kMac == null");
      }

      cipher.init(Cipher.ENCRYPT_MODE, kEnc, ZERO_IV_PARAM_SPEC);
      byte[] plaintext = new byte[32];
      System.arraycopy(rndIFD, 0, plaintext, 0, 8);
      System.arraycopy(rndICC, 0, plaintext, 8, 8);
      System.arraycopy(kIFD, 0, plaintext, 16, 16);
      byte[] ciphertext = cipher.doFinal(plaintext);
      if (ciphertext.length != 32) {
        throw new IllegalStateException("Cryptogram wrong length " + ciphertext.length);
      }

      mac.init(kMac);
      byte[] mactext = mac.doFinal(Util.pad(ciphertext, 8));
      if (mactext.length != 8) {
        throw new IllegalStateException("MAC wrong length");
      }

      byte p1 = (byte)0x00;
      byte p2 = (byte)0x00;

      byte[] data = new byte[32 + 8];
      System.arraycopy(ciphertext, 0, data, 0, 32);
      System.arraycopy(mactext, 0, data, 32, 8);
      int le = 40; /* 40 means max ne is 40 (0x28). */
      CommandAPDU capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_EXTERNAL_AUTHENTICATE, p1, p2, data, le);
      ResponseAPDU rapdu = service.transmit(capdu);

      if (rapdu == null) {
        throw new CardServiceException("Mutual authentication failed, received null response APDU");
      }

      byte[] rapduBytes = rapdu.getBytes();
      short sw = (short)rapdu.getSW();
      if (rapduBytes == null) {
        throw new CardServiceException("Mutual authentication failed, received empty data in response APDU", sw);
      }

      /* Some MRTDs apparently don't support 40 here, try again with 0. See R2-p1_v2_sIII_0035 (and other issues). */
      if (sw != ISO7816.SW_NO_ERROR) {
        le = 0; /* 0 means ne is max 256 (0xFF). */
        capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_EXTERNAL_AUTHENTICATE, p1, p2, data, le);
        rapdu = service.transmit(capdu);
        rapduBytes = rapdu.getBytes();
        sw = (short)rapdu.getSW();
      }

      if (rapduBytes.length != 42) {
        throw new AccessDeniedException("Mutual authentication failed: expected length: 40 + 2, actual length: " + rapduBytes.length, sw);
      }

      /* Decrypt the response. */
      cipher.init(Cipher.DECRYPT_MODE, kEnc, ZERO_IV_PARAM_SPEC);
      byte[] result = cipher.doFinal(rapduBytes, 0, rapduBytes.length - 8 - 2);
      if (result.length != 32) {
        /* The PICC allowed access, but probably the resulting secure channel will be wrong. */
        throw new CardServiceException("Cryptogram wrong length, was expecting 32, found " + result.length, sw);
      }

      return result;
    } catch (GeneralSecurityException gse) {
      /* Lower level security exception, probably the resulting secure channel will be wrong. */
      throw new CardServiceException("Security exception during mutual auth", gse);
    }
  }
}
