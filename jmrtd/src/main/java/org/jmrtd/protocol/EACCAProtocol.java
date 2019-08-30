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
 * $Id: EACCAProtocol.java 1805 2018-11-26 21:39:46Z martijno $
 */

package org.jmrtd.protocol;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;

import org.jmrtd.APDULevelEACCACapable;
import org.jmrtd.Util;
import org.jmrtd.lds.ChipAuthenticationInfo;
import org.jmrtd.lds.SecurityInfo;

import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.tlv.TLVUtil;

/**
 * The EAC Chip Authentication protocol (version 1).
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1805 $
 *
 * @since 0.5.6
 */
public class EACCAProtocol {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private static final Provider BC_PROVIDER = Util.getBouncyCastleProvider();

  private static final int COMMAND_CHAINING_CHUNK_SIZE = 224;

  private APDULevelEACCACapable service;

  private SecureMessagingWrapper wrapper;

  private int maxTranceiveLength;

  private boolean shouldCheckMAC;

  /**
   * Constructs a protocol instance.
   *
   * @param service the card service
   * @param wrapper the existing secure messaging wrapper
   * @param maxTranceiveLength the maximal tranceive length (on responses to {@code READ BINARY})
   *        to use in the resulting secure messaging channel
   * @param shouldCheckMAC whether the resulting secure messaging channel should apply strict MAC
   *        checking on response APDUs
   */
  public EACCAProtocol(APDULevelEACCACapable service, SecureMessagingWrapper wrapper, int maxTranceiveLength, boolean shouldCheckMAC) {
    this.service = service;
    this.wrapper = wrapper;
    this.maxTranceiveLength = maxTranceiveLength;
    this.shouldCheckMAC = shouldCheckMAC;
  }

  /**
   * Perform EAC-CA (Chip Authentication) part of EAC (version 1). For details see TR-03110
   * ver. 1.11. In short, we authenticate the chip with DH or ECDH key agreement
   * protocol and create new secure messaging keys.
   *
   * The newly established secure messaging wrapper is made available to the caller in
   * the result.
   *
   * @param keyId passport's public key id (stored in DG14), {@code null} if none
   * @param oid the object identifier indicating the Chip Authentication protocol
   * @param publicKeyOID the OID indicating the type of public key
   * @param piccPublicKey PICC's public key (stored in DG14)
   *
   * @return the Chip Authentication result
   *
   * @throws CardServiceException if Chip Authentication failed or some error occurred
   */
  public EACCAResult doCA(BigInteger keyId, String oid, String publicKeyOID, PublicKey piccPublicKey) throws CardServiceException {
    if (piccPublicKey == null) {
      throw new IllegalArgumentException("PICC public key is null");
    }

    String agreementAlg = ChipAuthenticationInfo.toKeyAgreementAlgorithm(oid);
    if (agreementAlg == null) {
      throw new IllegalArgumentException("Unknown agreement algorithm");
    }
    if (!("ECDH".equals(agreementAlg) || "DH".equals(agreementAlg))) {
      throw new IllegalArgumentException("Unsupported agreement algorithm, expected ECDH or DH, found " + agreementAlg);
    }

    if (oid == null) {
      oid = inferChipAuthenticationOIDfromPublicKeyOID(publicKeyOID);
    }

    try {
      AlgorithmParameterSpec params = null;
      if ("DH".equals(agreementAlg)) {
        DHPublicKey piccDHPublicKey = (DHPublicKey)piccPublicKey;
        params = piccDHPublicKey.getParams();
      } else if ("ECDH".equals(agreementAlg)) {
        ECPublicKey piccECPublicKey = (ECPublicKey)piccPublicKey;
        params = piccECPublicKey.getParams();
      }

      /* Generate the inspection system's ephemeral key pair. */
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(agreementAlg, BC_PROVIDER);
      keyPairGenerator.initialize(params);
      KeyPair pcdKeyPair = keyPairGenerator.generateKeyPair();
      PublicKey pcdPublicKey = pcdKeyPair.getPublic();
      PrivateKey pcdPrivateKey = pcdKeyPair.getPrivate();

      sendPublicKey(service, wrapper, oid, keyId, pcdPublicKey);

      byte[] keyHash = getKeyHash(agreementAlg, pcdPublicKey);

      byte[] sharedSecret = computeSharedSecret(agreementAlg, piccPublicKey, pcdPrivateKey);

      wrapper = restartSecureMessaging(oid, sharedSecret, maxTranceiveLength, shouldCheckMAC);

      return new EACCAResult(keyId, piccPublicKey, keyHash, pcdPublicKey, pcdPrivateKey, wrapper);
    } catch (GeneralSecurityException e) {
      throw new CardServiceException("Security exception during Chip Authentication", e);
    }
  }

  /**
   * Sends the PCD's public key to the PICC.
   *
   * @param service the card service
   * @param wrapper the existing secure messaging wrapper
   * @param oid the Chip Authentication object identifier
   * @param keyId a key identifier or {@code null}
   * @param pcdPublicKey the public key to send
   *
   * @throws CardServiceException on error
   */
  public static void sendPublicKey(APDULevelEACCACapable service, SecureMessagingWrapper wrapper, String oid, BigInteger keyId, PublicKey pcdPublicKey) throws CardServiceException {
    String agreementAlg = ChipAuthenticationInfo.toKeyAgreementAlgorithm(oid);
    String cipherAlg = ChipAuthenticationInfo.toCipherAlgorithm(oid);
    byte[] keyData = getKeyData(agreementAlg, pcdPublicKey);

    if (cipherAlg.startsWith("DESede")) {
      byte[] idData = null;
      if (keyId != null) {
        byte[] keyIdBytes = Util.i2os(keyId);
        idData = TLVUtil.wrapDO(0x84, keyIdBytes); /* FIXME: Constant for 0x84. */
      }
      service.sendMSEKAT(wrapper, TLVUtil.wrapDO(0x91, keyData), idData); /* FIXME: Constant for 0x91. */
    } else if (cipherAlg.startsWith("AES")) {
      service.sendMSESetATIntAuth(wrapper, oid, keyId);
      byte[] data = TLVUtil.wrapDO(0x80, keyData); /* FIXME: Constant for 0x80. */
      try {
        service.sendGeneralAuthenticate(wrapper, data, true);
      } catch (CardServiceException cse) {
        LOGGER.log(Level.WARNING, "Failed to send GENERAL AUTHENTICATE, falling back to command chaining", cse);
        List<byte[]> segments = Util.partition(COMMAND_CHAINING_CHUNK_SIZE, data);

        int index = 0;
        for (byte[] segment: segments) {
          service.sendGeneralAuthenticate(wrapper, segment, ++index >= segments.size());
        }
      }
    } else {
      throw new IllegalStateException("Cannot set up secure channel with cipher " + cipherAlg);
    }
  }

  /**
   * Performs the key agreement step.
   * Generates a secret based on the PICC's public key and the PCD's private key.
   *
   * @param agreementAlg the agreement algorithm
   * @param piccPublicKey the PICC's public key
   * @param pcdPrivateKey the PCD's private key
   *
   * @return the shared secret
   *
   * @throws NoSuchAlgorithmException if the agreement algorithm is unsupported
   *
   * @throws InvalidKeyException if one of the keys is invalid
   */
  public static byte[] computeSharedSecret(String agreementAlg, PublicKey piccPublicKey, PrivateKey pcdPrivateKey) throws NoSuchAlgorithmException, InvalidKeyException {
    KeyAgreement agreement = KeyAgreement.getInstance(agreementAlg, BC_PROVIDER);
    agreement.init(pcdPrivateKey);
    agreement.doPhase(piccPublicKey, true);
    return agreement.generateSecret();
  }

  /**
   * Restarts secure messaging based on the shared secret.
   *
   * @param oid the Chip Authentication object identifier
   * @param sharedSecret the shared secret
   * @param maxTranceiveLength the maximum APDU tranceive length
   * @param shouldCheckMAC whether to check MAC
   *
   * @return the secure messaging wrapper
   *
   * @throws GeneralSecurityException on error
   */
  public static SecureMessagingWrapper restartSecureMessaging(String oid, byte[] sharedSecret, int maxTranceiveLength, boolean shouldCheckMAC) throws GeneralSecurityException {
    String cipherAlg = ChipAuthenticationInfo.toCipherAlgorithm(oid);
    int keyLength = ChipAuthenticationInfo.toKeyLength(oid);

    /* Start secure messaging. */
    SecretKey ksEnc = Util.deriveKey(sharedSecret, cipherAlg, keyLength, Util.ENC_MODE);
    SecretKey ksMac = Util.deriveKey(sharedSecret, cipherAlg, keyLength, Util.MAC_MODE);

    if (cipherAlg.startsWith("DESede")) {
      return new DESedeSecureMessagingWrapper(ksEnc, ksMac, maxTranceiveLength, shouldCheckMAC, 0L);
    } else if (cipherAlg.startsWith("AES")) {
      return new AESSecureMessagingWrapper(ksEnc, ksMac, maxTranceiveLength, shouldCheckMAC, 0L);
    } else {
      throw new IllegalStateException("Unsupported cipher algorithm " + cipherAlg);
    }
  }

  /**
   * Returns the secure messaging wrapper currently in use.
   *
   * @return a secure messaging wrapper
   */
  public SecureMessagingWrapper getWrapper() {
    return wrapper;
  }

  /**
   * Returns the key hash which will be used as input for Terminal Authentication.
   *
   * @param agreementAlg the agreement algorithm, either {@code "DH"} or {@code "ECDH"}
   * @param pcdPublicKey the inspection system's public key
   *
   * @return the key hash
   *
   * @throws NoSuchAlgorithmException on error
   */
  public static byte[] getKeyHash(String agreementAlg, PublicKey pcdPublicKey) throws NoSuchAlgorithmException {
    if ("DH".equals(agreementAlg)) {
      /* TODO: this is probably wrong, what should be hashed? */
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      return md.digest(getKeyData(agreementAlg, pcdPublicKey));
    } else if ("ECDH".equals(agreementAlg)) {
      org.bouncycastle.jce.interfaces.ECPublicKey pcdECPublicKey = (org.bouncycastle.jce.interfaces.ECPublicKey)pcdPublicKey;
      byte[] t = Util.i2os(pcdECPublicKey.getQ().getAffineXCoord().toBigInteger());
      int keySize = (int)Math.ceil(pcdECPublicKey.getParameters().getCurve().getFieldSize() / 8.0);
      return Util.alignKeyDataToSize(t, keySize);
    }

    throw new IllegalArgumentException("Unsupported agreement algorithm " + agreementAlg);
  }

  /**
   * Returns the public key data to be sent.
   *
   * @param agreementAlg the agreement algorithm, either {@code "DH"} or {@code "ECDH"}
   * @param pcdPublicKey the inspection system's public key
   *
   * @return the key data
   */
  private static byte[] getKeyData(String agreementAlg, PublicKey pcdPublicKey) {
    if ("DH".equals(agreementAlg)) {
      DHPublicKey pcdDHPublicKey = (DHPublicKey)pcdPublicKey;
      return Util.i2os(pcdDHPublicKey.getY());
    } else if ("ECDH".equals(agreementAlg)) {
      org.bouncycastle.jce.interfaces.ECPublicKey pcdECPublicKey = (org.bouncycastle.jce.interfaces.ECPublicKey)pcdPublicKey;
      return pcdECPublicKey.getQ().getEncoded(false);
    }

    throw new IllegalArgumentException("Unsupported agreement algorithm " + agreementAlg);
  }

  /**
   * Infers the Chip Authentication OID from a Chip Authentication public key OID.
   * This is a best effort.
   *
   * @param publicKeyOID the Chip Authentication public key OID
   *
   * @return an OID or {@code null}
   */
  private static String inferChipAuthenticationOIDfromPublicKeyOID(String publicKeyOID) {
    if (SecurityInfo.ID_PK_ECDH.equals(publicKeyOID)) {
      /*
       * This seems to work for French passports (generation 2013, 2014),
       * but it is best effort.
       */
      LOGGER.warning("Could not determine ChipAuthentication algorithm, defaulting to id-CA-ECDH-3DES-CBC-CBC");
      return SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC;
    } else if (SecurityInfo.ID_PK_DH.equals(publicKeyOID)) {
      /*
       * Not tested. Best effort.
       */
      LOGGER.warning("Could not determine ChipAuthentication algorithm, defaulting to id-CA-DH-3DES-CBC-CBC");
      return SecurityInfo.ID_CA_DH_3DES_CBC_CBC;
    } else {
      LOGGER.warning("No ChipAuthenticationInfo and unsupported ChipAuthenticationPublicKeyInfo public key OID " + publicKeyOID);
    }

    return null;
  }
}
