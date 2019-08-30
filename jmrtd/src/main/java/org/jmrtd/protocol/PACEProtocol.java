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
 * $Id: PACEProtocol.java 1818 2019-08-02 12:59:22Z martijno $
 */

package org.jmrtd.protocol;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.jmrtd.APDULevelPACECapable;
import org.jmrtd.AccessKeySpec;
import org.jmrtd.BACKeySpec;
import org.jmrtd.PACEException;
import org.jmrtd.PACEKeySpec;
import org.jmrtd.PACESecretKeySpec;
import org.jmrtd.PassportService;
import org.jmrtd.Util;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.PACEInfo.DHCParameterSpec;
import org.jmrtd.lds.PACEInfo.MappingType;

import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVOutputStream;
import net.sf.scuba.tlv.TLVUtil;
import net.sf.scuba.util.Hex;

/**
 * The Password Authenticated Connection Establishment protocol.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1818 $
 *
 * @since 0.5.6
 */
public class PACEProtocol {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private static final Provider BC_PROVIDER = Util.getBouncyCastleProvider();

  /**
   * Used in the last step of PACE-CAM.
   *
   * From 9303-11:
   *
   * AES [19] SHALL be used in CBC-mode according to [ISO/IEC 10116]
   * with IV=E(KSEnc,-1), where -1 is the bit string of length 128
   * with all bits set to 1.
   */
  private static final byte[] IV_FOR_PACE_CAM_DECRYPTION = {
      (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
      (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
      (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
      (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
  };

  /** Constant used in IM pseudo random number mapping, see Doc 9303 - Part 11, 4.4.3.3.2. */
  /* a668892a7c41e3ca739f40b057d85904, 16 bytes, 128 bits  */
  private static final byte[] C0_LENGTH_128 =
    { (byte)0xA6, 0x68, (byte)0x89, 0x2A, 0x7C, 0x41, (byte)0xE3, (byte)0xCA, 0x73, (byte)0x9F, 0x40, (byte)0xB0, 0x57, (byte)0xD8, 0x59, 0x04 };

  /** Constant used in IM pseudo random number mapping, see Doc 9303 - Part 11, 4.4.3.3.2. */
  /* a4e136ac725f738b01c1f60217c188ad, 16 bytes, 128 bits */
  private static final byte[] C1_LENGTH_128 =
    { (byte)0xA4, (byte)0xE1, 0x36, (byte)0xAC, 0x72, 0x5F, 0x73, (byte)0x8B, 0x01, (byte)0xC1, (byte)0xF6, 0x02, 0x17, (byte)0xC1, (byte)0x88, (byte)0xAD };

  /** Constant used in IM pseudo random number mapping, see Doc 9303 - Part 11, 4.4.3.3.2. */
  /* d463d65234124ef7897054986dca0a174e28df758cbaa03f240616414d5a1676, 32 bytes, 256 bits */
  private static final byte[] C0_LENGTH_256 =
    { (byte)0xD4, 0x63, (byte)0xD6, 0x52, 0x34, 0x12, 0x4E, (byte)0xF7, (byte)0x89, 0x70, 0x54, (byte)0x98, 0x6D, (byte)0xCA, 0x0A, 0x17,
        0x4E, 0x28, (byte)0xDF, 0x75, (byte)0x8C, (byte)0xBA, (byte)0xA0, 0x3F, 0x24, 0x06, 0x16, 0x41, 0x4D, 0x5A, 0x16, 0x76 };

  /** Constant used in IM pseudo random number mapping, see Doc 9303 - Part 11, 4.4.3.3.2. */
  /* 54bd7255f0aaf831bec3423fcf39d69b6cbf066677d0faae5aadd99df8e53517, 32 bytes, 256 bits */
  private static final byte[] C1_LENGTH_256 =
    { 0x54, (byte)0xBD, 0x72, 0x55, (byte)0xF0, (byte)0xAA, (byte)0xF8, 0x31, (byte)0xBE, (byte)0xC3, 0x42, 0x3F, (byte)0xCF, 0x39, (byte)0xD6, (byte)0x9B,
        0x6C, (byte)0xBF, 0x06, 0x66, 0x77, (byte)0xD0, (byte)0xFA, (byte)0xAE, 0x5A, (byte)0xAD, (byte)0xD9, (byte)0x9D, (byte)0xF8, (byte)0xE5, 0x35, 0x17 };

  private APDULevelPACECapable service;

  private SecureMessagingWrapper wrapper;

  private int maxTranceiveLength;

  private boolean shouldCheckMAC;

  private Random random;

  /**
   * Constructs a PACE protocol instance.
   *
   * @param service the service for sending APDUs
   * @param wrapper the already established secure messaging channel (or {@code null})
   * @param maxTranceiveLength the maximal tranceive length (on responses to {@code READ BINARY})
   *        to use in the resulting secure messaging channel
   * @param shouldCheckMAC whether the resulting secure messaging channel should apply strict MAC
   *        checking on response APDUs
   */
  public PACEProtocol(APDULevelPACECapable service, SecureMessagingWrapper wrapper, int maxTranceiveLength, boolean shouldCheckMAC) {
    this.service = service;
    this.wrapper = wrapper;
    this.maxTranceiveLength = maxTranceiveLength;
    this.shouldCheckMAC = shouldCheckMAC;
    this.random = new SecureRandom();
  }

  /**
   * Performs the PACE 2.0 / SAC protocol.
   *
   * @param accessKey the MRZ or CAN based access key
   * @param oid as specified in the PACEInfo, indicates GM or IM or CAM, DH or ECDH, cipher, digest, length
   * @param params explicit static domain parameters for DH or ECDH
   *
   * @return a PACE result
   *
   * @throws CardServiceException if authentication failed or on some lower-level error
   */
  public PACEResult doPACE(AccessKeySpec accessKey, String oid, AlgorithmParameterSpec params) throws CardServiceException {
    try {
      return doPACE(accessKey, deriveStaticPACEKey(accessKey, oid), oid, params);
    } catch (GeneralSecurityException gse) {
      throw new PACEException("PCD side error in key derivation step", gse);
    }
  }

  /**
   * Performs the PACE 2.0 / SAC protocol.
   *
   * @param accessKey the key specification from which the static PACE key is derived
   * @param staticPACEKey the password key
   * @param oid as specified in the PACEInfo, indicates GM or IM or CAM, DH or ECDH, cipher, digest, length
   * @param staticParameters explicit static domain parameters the domain params for DH or ECDH
   *
   * @return a PACE result
   *
   * @throws CardServiceException if authentication failed or on lower level errors
   */
  private PACEResult doPACE(AccessKeySpec accessKey, SecretKey staticPACEKey, String oid, AlgorithmParameterSpec staticParameters) throws CardServiceException {
    MappingType mappingType = PACEInfo.toMappingType(oid); /* Either GM, CAM, or IM. */
    String agreementAlg = PACEInfo.toKeyAgreementAlgorithm(oid); /* Either DH or ECDH. */
    String cipherAlg  = PACEInfo.toCipherAlgorithm(oid); /* Either DESede or AES. */
    String digestAlg = PACEInfo.toDigestAlgorithm(oid); /* Either SHA-1 or SHA-256. */
    int keyLength = PACEInfo.toKeyLength(oid); /* Of the enc cipher. Either 128, 192, or 256. */

    checkConsistency(agreementAlg, cipherAlg, digestAlg, keyLength, staticParameters);

    Cipher staticPACECipher = null;
    try {
      staticPACECipher = Cipher.getInstance(cipherAlg + "/CBC/NoPadding");
    } catch (GeneralSecurityException gse) {
      throw new PACEException("PCD side error in static cipher construction during key derivation step", gse);
    }

    try {

      /* FIXME: multiple domain params feature not implemented here, for now. */
      byte[] referencePrivateKeyOrForComputingSessionKey = null;

      /* Send to the PICC. */
      byte paceKeyReference = PassportService.MRZ_PACE_KEY_REFERENCE;
      if (staticPACEKey instanceof PACESecretKeySpec) {
        paceKeyReference = ((PACESecretKeySpec)staticPACEKey).getKeyReference();
      }

      service.sendMSESetATMutualAuth(wrapper, oid, paceKeyReference, referencePrivateKeyOrForComputingSessionKey);
    } catch (CardServiceException cse) {
      throw new PACEException("PICC side error in static PACE key derivation step", cse, cse.getSW());
    }

    /*
     * PCD and PICC exchange a chain of general authenticate commands.
     * Steps 1 to 4 below correspond with steps in table 3.3 of
     * ICAO TR-SAC 1.01.
     */

    /*
     * Receive encrypted nonce z = E(K_pi, s).
     * Decrypt nonce s = D(K_pi, z).
     */
    byte[] piccNonce = doPACEStep1(staticPACEKey, staticPACECipher);

    /*
     * Receive additional data required for map, i.e.,
     * a public key from PICC, and (conditionally) a nonce t.
     * Compute ephemeral domain parameters D~ = Map(D_PICC, s).
     */

    PACEMappingResult mappingResult = doPACEStep2(mappingType, agreementAlg, staticParameters, piccNonce, staticPACECipher);
    AlgorithmParameterSpec ephemeralParams = mappingResult.getEphemeralParameters();

    /* Choose random ephemeral PCD side keys (SK_PCD~, PK_PCD~, D~). */
    KeyPair ephemeralPCDKeyPair = doPACEStep3GenerateKeyPair(agreementAlg, ephemeralParams);

    /*
     * Exchange PK_PCD~ and PK_PICC~ with PICC.
     * Check that PK_PCD~ and PK_PICC~ differ.
     */
    PublicKey ephemeralPICCPublicKey = doPACEStep3ExchangePublicKeys(ephemeralPCDKeyPair.getPublic(), ephemeralParams);

    /* Key agreement K = KA(SK_PCD~, PK_PICC~, D~). */
    byte[] sharedSecretBytes = doPACEStep3KeyAgreement(agreementAlg, ephemeralPCDKeyPair.getPrivate(), ephemeralPICCPublicKey);

    /* Derive secure messaging keys. */
    /* Compute session keys K_mac = KDF_mac(K), K_enc = KDF_enc(K). */
    SecretKey encKey = null;
    SecretKey macKey = null;
    try {
      encKey = Util.deriveKey(sharedSecretBytes, cipherAlg, keyLength, Util.ENC_MODE);
      macKey = Util.deriveKey(sharedSecretBytes, cipherAlg, keyLength, Util.MAC_MODE);
    } catch (GeneralSecurityException gse) {
      throw new PACEException("Security exception during secure messaging key derivation", gse);
    }

    /*
     * Compute authentication token T_PCD = MAC(K_mac, PK_PICC~).
     * Exchange authentication token T_PCD and T_PICC with PICC.
     * Check authentication token T_PICC.
     *
     * Extract encryptedChipAuthenticationData, if mapping is CAM.
     */
    byte[] encryptedChipAuthenticationData = doPACEStep4(oid, mappingType, ephemeralPCDKeyPair, ephemeralPICCPublicKey, macKey);
    byte[] chipAuthenticationData = null;
    /*
     * Start secure messaging.
     *
     * 4.6 of TR-SAC: If Secure Messaging is restarted, the SSC is used as follows:
     *  - The commands used for key agreement are protected with the old session keys and old SSC.
     *    This applies in particular for the response of the last command used for session key agreement.
     *  - The Send Sequence Counter is set to its new start value, i.e. within this specification the SSC is set to 0.
     *  - The new session keys and the new SSC are used to protect subsequent commands/responses.
     */
    try {
      long ssc = wrapper == null ? 0L : wrapper.getSendSequenceCounter();
      if (cipherAlg.startsWith("DESede")) {
        wrapper = new DESedeSecureMessagingWrapper(encKey, macKey, maxTranceiveLength, shouldCheckMAC, 0L);
      } else if (cipherAlg.startsWith("AES")) {
        wrapper = new AESSecureMessagingWrapper(encKey, macKey, maxTranceiveLength, shouldCheckMAC, ssc);
      } else {
        LOGGER.warning("Unsupported cipher algorithm " + cipherAlg);
      }
    } catch (GeneralSecurityException gse) {
      throw new IllegalStateException("Security exception in secure messaging establishment", gse);
    }

    if (MappingType.CAM.equals(mappingType)) {

      if (encryptedChipAuthenticationData == null) {
        LOGGER.warning("Encrypted Chip Authentication data is null");
      }

      /* Decrypt A_PICC to recover CA_PICC. */
      try {
        Cipher decryptCipher = Cipher.getInstance("AES/CBC/NoPadding");
        decryptCipher.init(Cipher.DECRYPT_MODE, encKey, new IvParameterSpec(IV_FOR_PACE_CAM_DECRYPTION));
        byte[] paddedChipAuthenticationData = decryptCipher.doFinal(encryptedChipAuthenticationData);
        chipAuthenticationData = Util.unpad(paddedChipAuthenticationData);
      } catch (GeneralSecurityException gse) {
        LOGGER.log(Level.WARNING, "Could not decrypt Chip Authentication data", gse);
      }

      /* CAM result. Include Chip Authentication data. */
      return new PACECAMResult(accessKey, agreementAlg, cipherAlg, digestAlg, keyLength,
          mappingResult, ephemeralPCDKeyPair, ephemeralPICCPublicKey,
          encryptedChipAuthenticationData, chipAuthenticationData, wrapper);
    }

    /* GM or IM result. */
    return new PACEResult(accessKey, mappingType, agreementAlg, cipherAlg, digestAlg, keyLength,
        mappingResult, ephemeralPCDKeyPair, ephemeralPICCPublicKey, wrapper);
  }

  /*
   * 1. Encrypted Nonce     - --- Absent        - 0x80 Encrypted Nonce
   *
   * Receive encrypted nonce z = E(K_pi, s).
   * (This is steps 1-3 in Table 4.4 in BSI 03111 2.0.)
   *
   * Decrypt nonce s = D(K_pi, z).
   * (This is step 4 in Table 4.4 in BSI 03111 2.0.)
   */
  /**
   * The first step in the PACE protocol receives an encrypted nonce from the PICC
   * and decrypts it.
   *
   * @param staticPACEKey the static PACE key
   * @param staticPACECipher the cipher to reuse
   *
   * @return the decrypted encrypted PICC nonce
   *
   * @throws PACEException on error
   */
  public byte[] doPACEStep1(SecretKey staticPACEKey, Cipher staticPACECipher) throws PACEException {
    byte[] piccNonce = null;
    try {
      byte[] step1Data = new byte[] { };
      /* Command data is empty. This implies an empty dynamic authentication object. */
      byte[] step1Response = service.sendGeneralAuthenticate(wrapper, step1Data, 256, false);
      byte[] step1EncryptedNonce = TLVUtil.unwrapDO(0x80, step1Response);

      /* (Re)initialize the K_pi cipher for decryption. */
      staticPACECipher.init(Cipher.DECRYPT_MODE, staticPACEKey, new IvParameterSpec(new byte[staticPACECipher.getBlockSize()])); // Fix proposed by Halvdan Grelland (halvdanhg@gmail.com)

      piccNonce = staticPACECipher.doFinal(step1EncryptedNonce);
      return piccNonce;
    } catch (GeneralSecurityException gse) {
      throw new PACEException("PCD side exception in tranceiving nonce step", gse);
    } catch (CardServiceException cse) {
      throw new PACEException("PICC side exception in tranceiving nonce step", cse);
    }
  }

  /*
   * 2. Map Nonce       - 0x81 Mapping Data     - 0x82 Mapping Data
   *
   * (This is step 3.a) in the protocol in TR-SAC.)
   * (This is step 5 in Table 4.4 in BSI 03111 2.0.)
   *
   * Receive additional data required for map (i.e. a public key from PICC, and (conditionally) a nonce t).
   * Compute ephemeral domain parameters D~ = Map(D_PICC, s).
   */
  /**
   * The second step in the PACE protocol computes ephemeral domain parameters
   * by mapping the PICC generated nonce (and optionally the PCD generated nonce,
   * which will be exchanged, in case of Integrated Mapping).
   *
   * @param mappingType either CAM, GM, or IM
   * @param agreementAlg the agreement algorithm, either DH or ECDH
   * @param params the static domain parameters
   * @param piccNonce the nonce received from the PICC
   * @param staticPACECipher the cipher to use in IM
   *
   * @return the newly computed ephemeral domain parameters
   *
   * @throws PACEException on error
   */
  public PACEMappingResult doPACEStep2(MappingType mappingType, String agreementAlg, AlgorithmParameterSpec params, byte[] piccNonce, Cipher staticPACECipher) throws PACEException {
    switch(mappingType) {
      case CAM:
        // Fall through to GM case.
      case GM:
        return doPACEStep2GM(agreementAlg, params, piccNonce);
      case IM:
        return doPACEStep2IM(agreementAlg, params, piccNonce, staticPACECipher);
      default:
        throw new PACEException("Unsupported mapping type " + mappingType);
    }
  }

  /**
   * The second step in the PACE protocol (GM case) computes ephemeral domain parameters
   * by performing a key agreement protocol with the PICC nonce as
   * input.
   *
   * @param agreementAlg the agreement algorithm, either DH or ECDH
   * @param params the static domain parameters
   * @param piccNonce the received nonce from the PICC
   *
   * @return the computed ephemeral domain parameters
   *
   * @throws PACEException on error
   */
  public PACEGMMappingResult doPACEStep2GM(String agreementAlg, AlgorithmParameterSpec params, byte[] piccNonce) throws PACEException {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(agreementAlg, BC_PROVIDER);
      keyPairGenerator.initialize(params);
      KeyPair pcdMappingKeyPair = keyPairGenerator.generateKeyPair();
      PublicKey pcdMappingPublicKey = pcdMappingKeyPair.getPublic();
      PrivateKey pcdMappingPrivateKey = pcdMappingKeyPair.getPrivate();

      byte[] pcdMappingEncodedPublicKey = encodePublicKeyForSmartCard(pcdMappingPublicKey);
      byte[] step2Data = TLVUtil.wrapDO(0x81, pcdMappingEncodedPublicKey);

      byte[] step2Response = service.sendGeneralAuthenticate(wrapper, step2Data, maxTranceiveLength, false);

      byte[] piccMappingEncodedPublicKey = TLVUtil.unwrapDO(0x82, step2Response);
      PublicKey piccMappingPublicKey = decodePublicKeyFromSmartCard(piccMappingEncodedPublicKey, params);

      if ("ECDH".equals(agreementAlg)) {
        /* Treat shared secret as an ECPoint. */
        PACEGMWithECDHAgreement mappingAgreement = new PACEGMWithECDHAgreement();
        mappingAgreement.init(pcdMappingPrivateKey);
        ECPoint mappingSharedSecretPoint = mappingAgreement.doPhase(piccMappingPublicKey);
        AlgorithmParameterSpec ephemeralParameters = mapNonceGMWithECDH(piccNonce, mappingSharedSecretPoint, (ECParameterSpec)params);
        return new PACEGMWithECDHMappingResult(params, piccNonce, piccMappingPublicKey, pcdMappingKeyPair, mappingSharedSecretPoint, ephemeralParameters);
      } else if ("DH".equals(agreementAlg)) {
        KeyAgreement mappingAgreement = KeyAgreement.getInstance(agreementAlg);
        mappingAgreement.init(pcdMappingPrivateKey);
        mappingAgreement.doPhase(piccMappingPublicKey, true);
        byte[] mappingSharedSecretBytes = mappingAgreement.generateSecret();
        AlgorithmParameterSpec ephemeralParameters = mapNonceGMWithDH(piccNonce, Util.os2i(mappingSharedSecretBytes), (DHParameterSpec)params);
        return new PACEGMWithDHMappingResult(params, piccNonce, piccMappingPublicKey, pcdMappingKeyPair, mappingSharedSecretBytes, ephemeralParameters);
      } else {
        throw new IllegalArgumentException("Unsupported parameters for mapping nonce, expected \"ECDH\" / ECParameterSpec or \"DH\" / DHParameterSpec"
            + ", found \"" + agreementAlg + "\" /" + params.getClass().getCanonicalName());
      }
    } catch (GeneralSecurityException gse) {
      throw new PACEException("PCD side error in mapping nonce step", gse);
    } catch (CardServiceException cse) {
      throw new PACEException("PICC side exception in mapping nonce step", cse);
    }
  }

  /*
   * The function Map:G -> G_Map is defined as
   * G_Map = f_G(R_p(s,t)),
   * where R_p() is a pseudo-random function that maps octet strings to elements of GF(p)
   * and f_G() is a function that maps elements of GF(p) to <G>.
   * The random nonce t SHALL be chosen randomly by the inspection system
   * and sent to the MRTD chip.
   * The pseudo-random function R_p() is described in Section 3.4.2.2.3.
   * The function f_G() is defined in [4] and [25].
   *
   * [4]: Brier, Eric; Coron, Jean-S&eacute;́bastien; Icart, Thomas; Madore, David; Randriam, Hugues; and
   *      Tibouch, Mehdi, Efficient Indifferentiable Hashing into Ordinary Elliptic Curves, Advances in
   *      Cryptology – CRYPTO 2010, Springer-Verlag, 2010.
   * [25]: Sagem, MorphoMapping Patents FR09-54043 and FR09-54053, 2009
   */
  /**
   * The second step in the PACE protocol computes ephemeral domain parameters
   * by performing a key agreement protocol with the PICC and PCD nonces as
   * input.
   *
   * @param agreementAlg the agreement algorithm, either DH or ECDH
   * @param params the static domain parameters
   * @param piccNonce the received nonce from the PICC
   * @param staticPACECipher the cipher to use for IM
   *
   * @return the computed ephemeral domain parameters
   *
   * @throws PACEException on error
   */
  public PACEIMMappingResult doPACEStep2IM(String agreementAlg, AlgorithmParameterSpec params, byte[] piccNonce, Cipher staticPACECipher) throws PACEException {
    try {

      byte[] pcdNonce = new byte[piccNonce.length];
      random.nextBytes(pcdNonce);

      byte[] step2Data = TLVUtil.wrapDO(0x81, pcdNonce);

      /*
       * NOTE: The context specific data object 0x82 SHALL be empty (TR SAC 3.3.2).
       */
      /* byte[] step2Response = */ service.sendGeneralAuthenticate(wrapper, step2Data, maxTranceiveLength, false);

      if ("ECDH".equals(agreementAlg)) {
        AlgorithmParameterSpec ephemeralParameters = mapNonceIMWithECDH(piccNonce, pcdNonce, staticPACECipher.getAlgorithm(), (ECParameterSpec)params);
        return new PACEIMMappingResult(params, piccNonce, pcdNonce, ephemeralParameters);
      } else if ("DH".equals(agreementAlg)) {
        AlgorithmParameterSpec ephemeralParameters = mapNonceIMWithDH(piccNonce, pcdNonce, staticPACECipher.getAlgorithm(), (DHParameterSpec)params);
        return new PACEIMMappingResult(params, piccNonce, pcdNonce, ephemeralParameters);
      } else {
        throw new IllegalArgumentException("Unsupported parameters for mapping nonce, expected \"ECDH\" / ECParameterSpec or \"DH\" / DHParameterSpec"
            + ", found \"" + agreementAlg + "\" /" + params.getClass().getCanonicalName());
      }
    } catch (GeneralSecurityException gse) {
      throw new PACEException("PCD side error in mapping nonce step", gse);
    } catch (CardServiceException cse) {
      throw new PACEException("PICC side exception in mapping nonce step", cse, cse.getSW());
    }
  }

  /* Choose a random ephemeral key pair. (SK_PCD~, PK_PCD~, D~). */
  /**
   * Chooses a random ephemeral key pair.
   *
   * @param agreementAlg the agreement algorithm
   * @param ephemeralParams the parameters
   *
   * @return the key pair
   *
   * @throws PACEException on error
   */
  public KeyPair doPACEStep3GenerateKeyPair(String agreementAlg, AlgorithmParameterSpec ephemeralParams) throws PACEException {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(agreementAlg, BC_PROVIDER);
      keyPairGenerator.initialize(ephemeralParams);
      return keyPairGenerator.generateKeyPair();
    } catch (GeneralSecurityException gse) {
      throw new PACEException("PCD side error during generation of PCD key pair", gse);
    }
  }

  /*
   * 3. Perform Key Agreement - 0x83 Ephemeral Public Key - 0x84 Ephemeral Public Key
   *
   * Exchange PK_PCD~ and PK_PICC~ with PICC.
   * Check that PK_PCD~ and PK_PICC~ differ.
   */
  /**
   * Sends the PCD's public key to the PICC and receives and interprets the PICC's public key in exchange.
   *
   * @param pcdPublicKey the PCD's public key
   * @param ephemeralParams the ephemeral parameters to interpret the PICC's public key
   *
   * @return the PICC's public key
   *
   * @throws PACEException on error
   */
  public PublicKey doPACEStep3ExchangePublicKeys(PublicKey pcdPublicKey, AlgorithmParameterSpec ephemeralParams)  throws PACEException {
    try {
      byte[] pcdEncodedPublicKey = encodePublicKeyForSmartCard(pcdPublicKey);
      byte[] step3Data = TLVUtil.wrapDO(0x83, pcdEncodedPublicKey);
      byte[] step3Response = service.sendGeneralAuthenticate(wrapper, step3Data, maxTranceiveLength, false);
      byte[] piccEncodedPublicKey = TLVUtil.unwrapDO(0x84, step3Response);
      PublicKey piccPublicKey = decodePublicKeyFromSmartCard(piccEncodedPublicKey, ephemeralParams);

      if (pcdPublicKey.equals(piccPublicKey)) {
        throw new PACEException("PCD's public key and PICC's public key are the same in key agreement step!");
      }

      return piccPublicKey;
    } catch (IllegalStateException ise) {
      throw new PACEException("PCD side exception in key agreement step", ise);
    } catch (GeneralSecurityException gse) {
      throw new PACEException("PCD side exception in key agreement step", gse);
    } catch (CardServiceException cse) {
      throw new PACEException("PICC side exception in key agreement step", cse, cse.getSW());
    }
  }

  /* Key agreement K = KA(SK_PCD~, PK_PICC~, D~). */
  /**
   * Performs the key agreement.
   *
   * @param agreementAlg the agreement algorithm, either {@code "DH"} or {@code "ECDH"}
   * @param pcdPrivateKey the PCD's private key
   * @param piccPublicKey the PICC's public key
   *
   * @return the shared secret
   *
   * @throws PACEException on error
   */
  public byte[] doPACEStep3KeyAgreement(String agreementAlg, PrivateKey pcdPrivateKey, PublicKey piccPublicKey) throws PACEException {
    try {
      KeyAgreement keyAgreement = KeyAgreement.getInstance(agreementAlg, BC_PROVIDER);
      keyAgreement.init(pcdPrivateKey);
      keyAgreement.doPhase(updateParameterSpec(piccPublicKey, pcdPrivateKey), true);
      return keyAgreement.generateSecret();
    } catch (GeneralSecurityException gse) {
      LOGGER.log(Level.WARNING, "PCD side error during key agreement", gse);
      throw new PACEException("PCD side error during key agreement");
    }
  }

  /*
   * 4. Mutual Authentication - 0x85 Authentication Token - 0x86 Authentication Token
   *
   * Compute authentication token T_PCD = MAC(K_mac, PK_PICC~).
   * Exchange authentication token T_PCD and T_PICC with PICC.
   * Check authentication token T_PICC.
   *
   * Extracts encryptedChipAuthenticationData, if mapping type id CAM.
   */
  /**
   * Exchanges authentication tokens.
   *
   * @param oid the object identifier
   * @param mappingType the mapping type (GM or IM)
   * @param pcdKeyPair the PCD's key pair
   * @param piccPublicKey the PICC's public key
   * @param macKey the MAC key to use
   *
   * @return possible encrypted chip authentication data (PACE-CAM case)
   *
   * @throws CardServiceException on error
   */
  public byte[] doPACEStep4(String oid, MappingType mappingType, KeyPair pcdKeyPair, PublicKey piccPublicKey, SecretKey macKey) throws CardServiceException {
    try {
      byte[] pcdToken = generateAuthenticationToken(oid, macKey, piccPublicKey);
      byte[] step4Data = TLVUtil.wrapDO(0x85, pcdToken);
      byte[] step4Response = service.sendGeneralAuthenticate(wrapper, step4Data, 256, true);
      TLVInputStream step4ResponseInputStream = new TLVInputStream(new ByteArrayInputStream(step4Response));
      try {
        int tag86 = step4ResponseInputStream.readTag();
        if (tag86 != 0x86) {
          LOGGER.warning("Was expecting tag 0x86, found: " + Integer.toHexString(tag86));
        }
        /* int piccTokenLength = */ step4ResponseInputStream.readLength();
        byte[] piccToken = step4ResponseInputStream.readValue();

        byte[] expectedPICCToken = generateAuthenticationToken(oid, macKey, pcdKeyPair.getPublic());
        if (!Arrays.equals(expectedPICCToken, piccToken)) {
          throw new GeneralSecurityException("PICC authentication token mismatch"
              + ", expectedPICCToken = " + Hex.bytesToHexString(expectedPICCToken)
              + ", piccToken = " + Hex.bytesToHexString(piccToken));
        }

        if (mappingType == MappingType.CAM) {
          int tag8A = step4ResponseInputStream.readTag();
          if (tag8A != 0x8A) {
            LOGGER.warning("Was expecting tag 0x8A, found: " + Integer.toHexString(tag8A));
          }
          /* int encryptedChipAuthenticationDataLength = */ step4ResponseInputStream.readLength();
          return step4ResponseInputStream.readValue();
        }
      } catch (IOException ioe) {
        LOGGER.log(Level.WARNING, "Could not parse step 4 response", ioe);
      } finally {
        try {
          step4ResponseInputStream.close();
        } catch (IOException ioe) {
          LOGGER.log(Level.FINE, "Exception closing stream", ioe);
        }
      }

      return null;
    } catch (GeneralSecurityException gse) {
      throw new PACEException("PCD side exception in authentication token generation step", gse);
    }
  }

  /**
   * Derives the static key K_pi.
   *
   * @param accessKey the key material from the MRZ
   * @param oid the PACE object identifier is needed to determine the cipher algorithm and the key length
   *
   * @return the derived key
   *
   * @throws GeneralSecurityException on error
   */
  public static SecretKey deriveStaticPACEKey(AccessKeySpec accessKey, String oid) throws GeneralSecurityException {
    String cipherAlg  = PACEInfo.toCipherAlgorithm(oid); /* Either DESede or AES. */
    int keyLength = PACEInfo.toKeyLength(oid); /* Of the enc cipher. Either 128, 192, or 256. */
    byte[] keySeed = computeKeySeedForPACE(accessKey);

    byte paceKeyReference = 0;
    if (accessKey instanceof PACEKeySpec) {
      paceKeyReference = ((PACEKeySpec)accessKey).getKeyReference();
    }

    return Util.deriveKey(keySeed, cipherAlg, keyLength, null, Util.PACE_MODE, paceKeyReference);
  }

  /**
   * Computes a key seed based on an access key.
   *
   * @param accessKey the access key
   *
   * @return a key seed for secure messaging keys
   *
   * @throws GeneralSecurityException on error
   */
  public static byte[] computeKeySeedForPACE(AccessKeySpec accessKey) throws GeneralSecurityException {
    if (accessKey == null) {
      throw new IllegalArgumentException("Access key cannot be null");
    }

    /* MRZ based key. */
    if (accessKey instanceof BACKeySpec) {
      BACKeySpec bacKey = (BACKeySpec)accessKey;
      String documentNumber = bacKey.getDocumentNumber();
      String dateOfBirth = bacKey.getDateOfBirth();
      String dateOfExpiry = bacKey.getDateOfExpiry();

      if (dateOfBirth == null || dateOfBirth.length() != 6) {
        throw new IllegalArgumentException("Wrong date format used for date of birth. Expected yyMMdd, found " + dateOfBirth);
      }
      if (dateOfExpiry == null || dateOfExpiry.length() != 6) {
        throw new IllegalArgumentException("Wrong date format used for date of expiry. Expected yyMMdd, found " + dateOfExpiry);
      }
      if (documentNumber == null) {
        throw new IllegalArgumentException("Wrong document number. Found " + documentNumber);
      }

      documentNumber = fixDocumentNumber(documentNumber);

      return computeKeySeedForPACE(documentNumber, dateOfBirth, dateOfExpiry);
    }

    if (accessKey instanceof PACEKeySpec) {
      return ((PACEKeySpec)accessKey).getKey();
    }

    LOGGER.warning("JMRTD doesn't recognize this type of access key, best effort key derivation!");
    return accessKey.getKey();
  }

  /* Generic Mapping. */

  /**
   * Maps the nonce  for the ECDH case
   * using Generic Mapping to get new parameters
   * (notably a new generator).
   *
   * @param nonceS the nonce received from the PICC
   * @param sharedSecretPointH the shared secret
   * @param staticParameters the static parameters
   *
   * @return the new parameters
   */
  public static ECParameterSpec mapNonceGMWithECDH(byte[] nonceS, ECPoint sharedSecretPointH, ECParameterSpec staticParameters) {
    /*
     * D~ = (p, a, b, G~, n, h) where G~ = [s]G + H
     */
    ECPoint generator = staticParameters.getGenerator();
    EllipticCurve curve = staticParameters.getCurve();
    BigInteger a = curve.getA();
    BigInteger b = curve.getB();
    ECFieldFp field = (ECFieldFp)curve.getField();
    BigInteger p = field.getP();
    BigInteger order = staticParameters.getOrder();
    int cofactor = staticParameters.getCofactor();
    ECPoint ephemeralGenerator = Util.add(Util.multiply(Util.os2i(nonceS), generator, staticParameters), sharedSecretPointH, staticParameters);
    if (!Util.toBouncyCastleECPoint(ephemeralGenerator, staticParameters).isValid()) {
      LOGGER.info("ephemeralGenerator is not a valid point");
    }
    return new ECParameterSpec(new EllipticCurve(new ECFieldFp(p), a, b), ephemeralGenerator, order, cofactor);
  }

  /**
   * Maps the nonce for the DH case using Generic Mapping
   * to get new parameters
   * (notably a new generator).
   *
   * @param nonceS the nonce received from the PICC
   * @param sharedSecretH the shared secret point
   * @param staticParameters the static parameters
   *
   * @return the new parameters
   */
  public static DHParameterSpec mapNonceGMWithDH(byte[] nonceS, BigInteger sharedSecretH, DHParameterSpec staticParameters) {
    // g~ = g^s * h
    BigInteger p = staticParameters.getP();
    BigInteger generator = staticParameters.getG();
    BigInteger mappedGenerator = generator.modPow(Util.os2i(nonceS), p).multiply(sharedSecretH).mod(p);
    return new DHParameterSpec(p, mappedGenerator, staticParameters.getL());
  }

  /* Integrated Mapping. */

  /**
   * Transforms the nonces using a pseudo random number function and maps the resulting value to a point on the curve.
   * The resulting point is used as a generator as part of the returned domain parameters.
   *
   * @param nonceS the nonce from the PICC
   * @param nonceT the nonce from the PCD
   * @param cipherAlgorithm the cipher algorithm to be used by the pseudo random function (either {@code "AES"} or {@code "DESede"})
   * @param params the static domain parameters
   *
   * @return the newly computed domain parameters
   *
   * @throws GeneralSecurityException on error
   */
  public static AlgorithmParameterSpec mapNonceIMWithECDH(byte[] nonceS, byte[] nonceT, String cipherAlgorithm, ECParameterSpec params) throws GeneralSecurityException {
    BigInteger p = Util.getPrime(params);
    BigInteger order = params.getOrder();
    int cofactor = params.getCofactor();
    BigInteger a = params.getCurve().getA();
    BigInteger b = params.getCurve().getB();

    BigInteger t = Util.os2i(pseudoRandomFunction(nonceS, nonceT, p, cipherAlgorithm));

    ECPoint mappedGenerator = icartPointEncode(t, params);
    return new ECParameterSpec(new EllipticCurve(new ECFieldFp(p), a, b), mappedGenerator, order, cofactor);
  }

  /*
   * The function Map: g -> g~ is defined as g~ = f_g(R_p(s, t)), where R_p() is the pseudo-random function
   * that maps octet strings to elements of GF(p) and f_g() is a function that maps elements of GF(p) to
   * <g>. The random nonce t SHALL be chosen randomly by the inspection system and sent to the MRTD
   * chip. The pseudo-random function R_p() is described in Section 4.3.3. The function f_g() is defined as
   * f_g(x) = x^a mod p, and a = (p-1)/q is the cofactor. Implementations MUST check that g~ != 1.
   *
   * NOTE: The public key validation method described in RFC 2631 MUST be used to
   * prevent small subgroup attacks.
   */
  /**
   * Transforms the nonces using a pseudo random number function and maps the resulting value to a field element.
   * The resulting field element is used as a generator as part of the returned domain parameters.
   *
   * @param nonceS the nonce from the PICC
   * @param nonceT the nonce from the PCD
   * @param cipherAlgorithm the cipher algorithm to be used by the pseudo random function (either {@code "AES"} or {@code "DESede"})
   * @param params the static domain parameters
   *
   * @return the newly computed domain parameters
   *
   * @throws GeneralSecurityException on error
   */
  public static AlgorithmParameterSpec mapNonceIMWithDH(byte[] nonceS, byte[] nonceT, String cipherAlgorithm, DHParameterSpec params) throws GeneralSecurityException {
    BigInteger g = params.getG();
    if (g == null || g.equals(BigInteger.ONE)) {
      throw new IllegalArgumentException("Invalid generator: " + g);
    }

    BigInteger p = params.getP();

    BigInteger q = params instanceof DHCParameterSpec ? ((DHCParameterSpec)params).getQ() : BigInteger.ONE; // FIXME: What if q not available? We use 1 here? Should be p-1? -- MO

    BigInteger x = Util.os2i(pseudoRandomFunction(nonceS, nonceT, p, cipherAlgorithm));

    BigInteger a = p.subtract(BigInteger.ONE).divide(q);

    BigInteger mappedGenerator = x.modPow(a, p);
    return new DHParameterSpec(p, mappedGenerator, params.getL());
  }

  /*
   * The function R_p(s,t) is a function that maps octet strings s (of bit length l) and t (of bit length k)
   * to an element int(x_1 || x_2 || ... || x_n) mod p of GF(p).
   * The function R(s,t) is specified in Figure 2.
   * The construction is based on the respective block cipher E() in CBC mode according to ISO/IEC 10116 [12]
   * with IV=0, where k is the key size (in bits) of E().
   * Where required, the output k_i MUST be truncated to key size k.
   * The value n SHALL be selected as smallest number, such that n*l >= log2 p + 64.
   */
  /**
   * Pseudo random number function as specified in Doc 9303 - Part 11, 4.4.3.3.2.
   * Used in PACE IM.
   *
   * @param s the nonce that was sent by the ICC
   * @param t the nonce that was generated by the PCD
   * @param p the order of the prime field
   * @param algorithm the algorithm for block cipher E (either {@code "AES"} or {@code "DESede"})
   *
   * @return the resulting x
   *
   * @throws GeneralSecurityException on cryptographic error
   */
  public static byte[] pseudoRandomFunction(byte[] s, byte[] t, BigInteger p, String algorithm) throws GeneralSecurityException {
    if (s == null || t == null) {
      throw new IllegalArgumentException("Null nonce");
    }

    int l = s.length * 8;
    int k = t.length * 8; /* Key size in bits. */

    byte[] c0 = null;
    byte[] c1 = null;
    switch (l) {
      case 128:
        c0 = C0_LENGTH_128;
        c1 = C1_LENGTH_128;
        break;
      case 192: // Fall through
      case 256:
        c0 = C0_LENGTH_256;
        c1 = C1_LENGTH_256;
        break;
      default:
        throw new IllegalArgumentException("Unknown length " + l + ", was expecting 128, 192, or 256");
    }

    Cipher cipher = Cipher.getInstance(algorithm + (algorithm.endsWith("/CBC/NoPadding") ? "" : "/CBC/NoPadding"));
    int blockSize = cipher.getBlockSize(); /* in bytes */

    IvParameterSpec zeroIV = new IvParameterSpec(new byte[blockSize]);

    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(t, algorithm), zeroIV);
    byte[] key = cipher.doFinal(s);

    ByteArrayOutputStream x = new ByteArrayOutputStream();

    try {
      int n = 0;
      while (n * l < p.bitLength() + 64) {
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, 0, k / 8, algorithm), zeroIV);
        key = cipher.doFinal(c0);
        x.write(cipher.doFinal(c1));
        n++;
      }

      byte[] xBytes = x.toByteArray();
      return Util.i2os(Util.os2i(xBytes).mod(p));
    } catch (Exception ioe) {
      /* NOTE: Never happens, writing to byte array output stream. */
      LOGGER.log(Level.WARNING, "Could not write to stream", ioe);

      return Util.i2os(Util.os2i(x.toByteArray()).mod(p));
    } finally {
      try {
        x.close();
      } catch (IOException ioe) {
        LOGGER.log(Level.FINE, "Could not close stream", ioe);
      }
    }
  }

  /*
   * Icart's point encoding.
   * For now this is based on the implementation for affine coordinates
   * as described in ICAO SAC TR 2010, Section 5.2.
   */
  /**
   * Icart's point encoding for Elliptic Curve over a prime field.
   * This maps a field element to a point on the curve.
   * Used in PACE IM ECDH.
   *
   * @param t the field element to encode
   * @param params the parameters describing the curve and field
   *
   * @return the point on the curve that the input is mapped to
   */
  public static ECPoint icartPointEncode(BigInteger t, ECParameterSpec params) {
    BigInteger p = Util.getPrime(params);
    int cofactor = params.getCofactor();
    BigInteger a = params.getCurve().getA();
    BigInteger b = params.getCurve().getB();

    /* 1. */
    BigInteger alpha = t.modPow(BigInteger.valueOf(2), p).negate().mod(p);

    /* 2. (Using implementation note 5.2.2). */
    BigInteger alphaSq = alpha.modPow(BigInteger.valueOf(2), p);
    BigInteger alphaPlusAlphaSq = alpha.add(alphaSq).mod(p);
    BigInteger onePlusAlphaPlusAlphaSq = BigInteger.ONE.add(alphaPlusAlphaSq);
    BigInteger pMinus2 = p.subtract(BigInteger.ONE).subtract(BigInteger.ONE);
    BigInteger x2 = b.negate().multiply(onePlusAlphaPlusAlphaSq).multiply(a.multiply(alphaPlusAlphaSq).modPow(pMinus2, p)).mod(p);

    /* 3. */
    BigInteger x3 = alpha.multiply(x2).mod(p);

    /* 4. */
    BigInteger h2 = x2.modPow(BigInteger.valueOf(3), p).add(a.multiply(x2)).add(b).mod(p);

    /* 5. (Why are we calculating this?) */
    //    BigInteger h3 = x3.modPow(BigInteger.valueOf(3), p).add(a.multiply(x3)).add(b).mod(p);

    /* 6. */
    BigInteger u = t.modPow(BigInteger.valueOf(3), p).multiply(h2).mod(p);

    /* 7. */
    BigInteger pPlusOneOverFour = p.add(BigInteger.ONE).multiply(BigInteger.valueOf(4).modInverse(p)).mod(p);
    BigInteger pMinusOneMinusPPlusOneOverFour = p.subtract(BigInteger.ONE).subtract(pPlusOneOverFour);
    BigInteger aa = h2.modPow(pMinusOneMinusPPlusOneOverFour, p);

    BigInteger aaSqTimesH2 = aa.modPow(BigInteger.valueOf(2), p).multiply(h2).mod(p);

    ECPoint xy = aaSqTimesH2.equals(BigInteger.ONE) ? new ECPoint(x2, aa.multiply(h2).mod(p)) : new ECPoint(x3, aa.multiply(u).mod(p));

    if (cofactor == 1) {
      return Util.normalize(xy, params);
    } else {
      org.bouncycastle.math.ec.ECPoint bcPoint = Util.toBouncyCastleECPoint(xy, params);
      bcPoint.multiply(BigInteger.valueOf(cofactor));
      return Util.fromBouncyCastleECPoint(bcPoint);
    }
  }

  /**
   * Updates the parameters of the given public key to match the parameters of the given private key.
   *
   * @param publicKey the public key, should be an EC public key
   * @param privateKey the private key, should be an EC private key
   *
   * @return a new public key that uses the parameters of the private key
   *
   * @throws GeneralSecurityException on security error, or when keys are not EC
   */
  public static PublicKey updateParameterSpec(PublicKey publicKey, PrivateKey privateKey) throws GeneralSecurityException {
    String publicKeyAlgorithm = publicKey.getAlgorithm();
    String privateKeyAlgorithm = privateKey.getAlgorithm();

    if ("EC".equals(publicKeyAlgorithm) || "ECDH".equals(publicKeyAlgorithm)) {
      if (!("EC".equals(privateKeyAlgorithm) || "ECDH".equals(privateKeyAlgorithm))) {
        throw new NoSuchAlgorithmException("Unsupported key type public: " + publicKeyAlgorithm + ", private: " + privateKeyAlgorithm);
      }
      KeyFactory keyFactory = KeyFactory.getInstance("EC", BC_PROVIDER);
      KeySpec keySpec = new ECPublicKeySpec(((ECPublicKey)publicKey).getW(), ((ECPrivateKey)privateKey).getParams());
      return keyFactory.generatePublic(keySpec);
    } else if ("DH".equals(publicKeyAlgorithm)) {
      if (!("DH".equals(privateKeyAlgorithm))) {
        throw new NoSuchAlgorithmException("Unsupported key type public: " + publicKeyAlgorithm + ", private: " + privateKeyAlgorithm);
      }
      KeyFactory keyFactory = KeyFactory.getInstance("DH");
      DHPublicKey dhPublicKey = (DHPublicKey)publicKey;
      DHPrivateKey dhPrivateKey = (DHPrivateKey)privateKey;
      DHParameterSpec privateKeyParams = dhPrivateKey.getParams();
      KeySpec keySpec = new DHPublicKeySpec(dhPublicKey.getY(), privateKeyParams.getP(), privateKeyParams.getG());
      return keyFactory.generatePublic(keySpec);
    } else {
      throw new NoSuchAlgorithmException("Unsupported key type public: " + publicKeyAlgorithm + ", private: " + privateKeyAlgorithm);
    }
  }

  /**
   * Generates an authentication token.
   * The authentication token SHALL be computed over a public key data object (cf. Section 4.5)
   * containing the object identifier as indicated in MSE:Set AT (cf. Section 3.2.1), and the
   * received ephemeral public key (i.e. excluding the domain parameters, cf. Section 4.5.3)
   * using an authentication code and the key KS MAC derived from the key agreement.
   *
   * @param oid the object identifier as indicated in MSE Set AT
   * @param macKey the KS MAC key derived from the key agreement
   * @param publicKey the received public key
   *
   * @return the authentication code
   *
   * @throws GeneralSecurityException on error while performing the MAC operation
   */
  public static byte[] generateAuthenticationToken(String oid, SecretKey macKey, PublicKey publicKey) throws GeneralSecurityException {
    String cipherAlg = PACEInfo.toCipherAlgorithm(oid);
    String macAlg = inferMACAlgorithmFromCipherAlgorithm(cipherAlg);
    Mac mac = Util.getMac(macAlg, macKey);
    return generateAuthenticationToken(oid, mac, publicKey);
  }

  /**
   * Computes a key seed given a card access number (CAN).
   *
   * @param cardAccessNumber the card access number
   *
   * @return a key seed for deriving secure messaging keys
   *
   * @throws GeneralSecurityException on error
   */
  public static byte[] computeKeySeedForPACE(String cardAccessNumber) throws GeneralSecurityException {
    return Util.computeKeySeed(cardAccessNumber, "SHA-1", false);
  }

  /**
   * Based on TR-SAC 1.01 4.5.1 and 4.5.2.
   *
   * For signing authentication token, not for sending to smart card.
   * Assumes context is known.
   *
   * @param oid object identifier
   * @param publicKey public key
   *
   * @return encoded public key data object for signing as authentication token
   *
   * @throws InvalidKeyException when public key is not DH or EC
   */
  public static byte[] encodePublicKeyDataObject(String oid, PublicKey publicKey) throws InvalidKeyException {
    return encodePublicKeyDataObject(oid, publicKey, true);
  }

  /**
   * Based on TR-SAC 1.01 4.5.1 and 4.5.2.
   *
   * For signing authentication token, not for sending to smart card.
   *
   * @param oid object identifier
   * @param publicKey public key
   * @param isContextKnown whether context of public key is known to receiver (we will not include domain parameters in that case).
   *
   * @return encoded public key data object for signing as authentication token
   *
   * @throws InvalidKeyException when public key is not DH or EC
   */
  public static byte[] encodePublicKeyDataObject(String oid, PublicKey publicKey, boolean isContextKnown) throws InvalidKeyException {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    TLVOutputStream tlvOutputStream = new TLVOutputStream(byteArrayOutputStream);
    try {
      tlvOutputStream.writeTag(0x7F49); // FIXME: constant for 7F49 */
      if (publicKey instanceof DHPublicKey) {
        DHPublicKey dhPublicKey = (DHPublicKey)publicKey;
        DHParameterSpec params = dhPublicKey.getParams();
        BigInteger p = params.getP();
        int l = params.getL();
        BigInteger generator = params.getG();
        BigInteger y = dhPublicKey.getY();

        tlvOutputStream.write(new ASN1ObjectIdentifier(oid).getEncoded()); /* Object Identifier, NOTE: encoding already contains 0x06 tag  */
        if (!isContextKnown) {
          /* p: Prime modulus */
          tlvOutputStream.writeTag(0x81);
          tlvOutputStream.writeValue(Util.i2os(p));

          /* q: Order of the subgroup */
          tlvOutputStream.writeTag(0x82);
          tlvOutputStream.writeValue(Util.i2os(BigInteger.valueOf(l)));

          /* Generator */
          tlvOutputStream.writeTag(0x83);
          tlvOutputStream.writeValue(Util.i2os(generator));
        }

        /* y: Public value */
        tlvOutputStream.writeTag(0x84);
        tlvOutputStream.writeValue(Util.i2os(y));
      } else if (publicKey instanceof ECPublicKey) {
        ECPublicKey ecPublicKey = (ECPublicKey)publicKey;
        ECParameterSpec params = ecPublicKey.getParams();
        BigInteger p = Util.getPrime(params);
        EllipticCurve curve = params.getCurve();
        BigInteger a = curve.getA();
        BigInteger b = curve.getB();
        ECPoint generator = params.getGenerator();
        BigInteger order = params.getOrder();
        int coFactor = params.getCofactor();
        ECPoint publicPoint = ecPublicKey.getW();

        /* Object Identifier, NOTE: encoding already contains 0x06 tag */
        tlvOutputStream.write(new ASN1ObjectIdentifier(oid).getEncoded());

        if (!isContextKnown) {
          /* Prime modulus */
          tlvOutputStream.writeTag(0x81);
          tlvOutputStream.writeValue(Util.i2os(p));

          /* First coefficient */
          tlvOutputStream.writeTag(0x82);
          tlvOutputStream.writeValue(Util.i2os(a));

          /* Second coefficient */
          tlvOutputStream.writeTag(0x83);
          tlvOutputStream.writeValue(Util.i2os(b));
          BigInteger affineX = generator.getAffineX();
          BigInteger affineY = generator.getAffineY();

          /* Base point, FIXME: correct encoding? */
          tlvOutputStream.writeTag(0x84);
          tlvOutputStream.write(Util.i2os(affineX));
          tlvOutputStream.write(Util.i2os(affineY));
          tlvOutputStream.writeValueEnd();

          /* Order of the base point */
          tlvOutputStream.writeTag(0x85);
          tlvOutputStream.writeValue(Util.i2os(order));
        }

        /* Public point */
        tlvOutputStream.writeTag(0x86);
        tlvOutputStream.writeValue(Util.ecPoint2OS(publicPoint));

        if (!isContextKnown) {
          /* Cofactor */
          tlvOutputStream.writeTag(0x87);
          tlvOutputStream.writeValue(Util.i2os(BigInteger.valueOf(coFactor)));
        }
      } else {
        throw new InvalidKeyException("Unsupported public key: " + publicKey.getClass().getCanonicalName());
      }
      tlvOutputStream.writeValueEnd(); /* 7F49 */
      tlvOutputStream.flush();
    } catch (IOException ioe) {
      LOGGER.log(Level.WARNING, "Exception", ioe);
      throw new IllegalStateException("Error in encoding public key");
    } finally {
      try {
        tlvOutputStream.close();
      } catch (IOException ioe) {
        LOGGER.log(Level.FINE, "Error closing stream", ioe);
      }
    }
    return byteArrayOutputStream.toByteArray();
  }

  /**
   * Write uncompressed coordinates (for EC) or public value (DH).
   *
   * @param publicKey public key
   *
   * @return encoding for smart card
   *
   * @throws InvalidKeyException if the key type is not EC or DH
   */
  public static byte[] encodePublicKeyForSmartCard(PublicKey publicKey) throws InvalidKeyException {
    if (publicKey == null) {
      throw new IllegalArgumentException("Cannot encode null public key");
    }
    if (publicKey instanceof ECPublicKey) {
      ECPublicKey ecPublicKey = (ECPublicKey)publicKey;
      try {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        bOut.write(Util.ecPoint2OS(ecPublicKey.getW()));
        byte[] encodedPublicKey = bOut.toByteArray();
        bOut.close();
        return encodedPublicKey;
      } catch (IOException ioe) {
        /* NOTE: Should never happen, we're writing to a ByteArrayOutputStream. */
        throw new IllegalStateException("Internal error writing to memory", ioe);
      }
    } else if (publicKey instanceof DHPublicKey) {
      DHPublicKey dhPublicKey = (DHPublicKey)publicKey;
      return Util.i2os(dhPublicKey.getY());
    } else {
      throw new InvalidKeyException("Unsupported public key: " + publicKey.getClass().getCanonicalName());
    }
  }

  /**
   * Decodes a public key received from the PICC.
   *
   * @param encodedPublicKey the encoded public key that was received
   * @param params the parameters used for interpreting the public key
   *
   * @return the decoded public key object
   */
  public static PublicKey decodePublicKeyFromSmartCard(byte[] encodedPublicKey, AlgorithmParameterSpec params) {
    if (params == null) {
      throw new IllegalArgumentException("Params cannot be null");
    }

    try {
      if (params instanceof ECParameterSpec) {
        ECPoint w = Util.os2ECPoint(encodedPublicKey);
        ECParameterSpec ecParams = (ECParameterSpec)params;
        return Util.getPublicKey("EC", new ECPublicKeySpec(w, ecParams));
      } else if (params instanceof DHParameterSpec) {
        BigInteger y = Util.os2i(encodedPublicKey);
        DHParameterSpec dhParams = (DHParameterSpec)params;
        return Util.getPublicKey("DH", new DHPublicKeySpec(y, dhParams.getP(), dhParams.getG()));
      }

      throw new IllegalArgumentException("Expected ECParameterSpec or DHParameterSpec, found " + params.getClass().getCanonicalName());
    } catch (GeneralSecurityException gse) {
      LOGGER.log(Level.WARNING, "Exception", gse);
      throw new IllegalArgumentException(gse);
    }
  }

  /**
   * Generates an authentication token.
   *
   * @param oid the object identifier as indicated in MSE Set AT
   * @param mac the MAC which has already been initialized with the MAC key derived from key agreement
   * @param publicKey the received public key
   *
   * @return the authentication token
   *
   * @throws GeneralSecurityException on error while performing the MAC operation
   */
  private static byte[] generateAuthenticationToken(String oid, Mac mac, PublicKey publicKey) throws GeneralSecurityException {
    byte[] encodedPublicKeyDataObject = encodePublicKeyDataObject(oid, publicKey);
    byte[] maccedPublicKeyDataObject = mac.doFinal(encodedPublicKeyDataObject);

    /* Output length needs to be 64 bits, copy first 8 bytes. */
    byte[] authenticationToken = new byte[8];
    System.arraycopy(maccedPublicKeyDataObject, 0, authenticationToken, 0, authenticationToken.length);
    return authenticationToken;
  }

  /**
   * Fixes the document number so that it is in MRZ format.
   * This replaces white spaces with fillers and
   * makes sure the length is at least 9.
   *
   * @param documentNumber the document number
   *
   * @return a fixed document number
   */
  private static String fixDocumentNumber(String documentNumber) {

    /* The document number, excluding trailing '<'. */
    String minDocumentNumber = documentNumber.replace('<', ' ').trim().replace(' ', '<');

    /* The document number, including trailing '<' until length 9. */
    StringBuilder result = new StringBuilder(minDocumentNumber);
    while (result.length() < 9) {
      result.append('<');
    }
    return result.toString();
  }

  /**
   * Computes the static key seed to be used in PACE KDF, based on information from the MRZ.
   *
   * @param documentNumber a string containing the document number
   * @param dateOfBirth a string containing the date of birth (YYMMDD)
   * @param dateOfExpiry a string containing the date of expiry (YYMMDD)
   *
   * @return a byte array of length 16 containing the key seed
   *
   * @throws GeneralSecurityException on security error
   */
  private static byte[] computeKeySeedForPACE(String documentNumber, String dateOfBirth, String dateOfExpiry) throws GeneralSecurityException {
    return Util.computeKeySeed(documentNumber, dateOfBirth, dateOfExpiry, "SHA-1", false);
  }

  /**
   * Checks consistency of input parameters.
   *
   * @param agreementAlg the agreement algorithm derived from the object identifier
   * @param cipherAlg the cipher algorithm derived from the object identifier
   * @param digestAlg the digest algorithm derived from the object identifier
   * @param keyLength the key length algorithm derived from the object identifier
   * @param params the parameters
   */
  private void checkConsistency(String agreementAlg, String cipherAlg, String digestAlg, int keyLength, AlgorithmParameterSpec params) {
    if (agreementAlg == null) {
      throw new IllegalArgumentException("Unknown agreement algorithm");
    }

    /* Agreement algorithm should be ECDH or DH. */
    if (!("ECDH".equalsIgnoreCase(agreementAlg) || "DH".equalsIgnoreCase(agreementAlg))) {
      throw new IllegalArgumentException("Unsupported agreement algorithm, expected ECDH or DH, found \"" + agreementAlg + "\"");
    }

    if (cipherAlg == null) {
      throw new IllegalArgumentException("Unknown cipher algorithm");
    }

    if (!("DESede".equalsIgnoreCase(cipherAlg) || "AES".equalsIgnoreCase(cipherAlg))) {
      throw new IllegalArgumentException("Unsupported cipher algorithm, expected DESede or AES, found \"" + cipherAlg + "\"");
    }

    if (!("SHA-1".equalsIgnoreCase(digestAlg) || "SHA1".equalsIgnoreCase(digestAlg)
        || "SHA-256".equalsIgnoreCase(digestAlg) || "SHA256".equalsIgnoreCase(digestAlg))) {
      throw new IllegalArgumentException("Unsupported cipher algorithm, expected DESede or AES, found \"" + digestAlg + "\"");
    }

    if (!(keyLength == 128 || keyLength == 192 || keyLength == 256)) {
      throw new IllegalArgumentException("Unsupported key length, expected 128, 192, or 256, found " + keyLength);
    }

    /* Params should be correct param spec type, given agreement algorithm. */
    if ("ECDH".equalsIgnoreCase(agreementAlg) && !(params instanceof ECParameterSpec)) {
      throw new IllegalArgumentException("Expected ECParameterSpec for agreement algorithm \"" + agreementAlg + "\", found " + params.getClass().getCanonicalName());
    } else if ("DH".equalsIgnoreCase(agreementAlg) && !(params instanceof DHParameterSpec)) {
      throw new IllegalArgumentException("Expected DHParameterSpec for agreement algorithm \"" + agreementAlg + "\", found " + params.getClass().getCanonicalName());
    }
  }

  /**
   * Infers a MAC algorithm given a encryption algorithm.
   *
   * @param cipherAlg the encryption algorithm.
   * If 3-DES is used for encryption, then the MAC algorithm is ISO9797 algorithm 3.
   * If AES is used for encryption, the the MAC algorithm is AES-CMAC.
   *
   * @return the MAC algorithm
   *
   * @throws InvalidAlgorithmParameterException for unknown encryption algorithm
   */
  private static String inferMACAlgorithmFromCipherAlgorithm(String cipherAlg) throws InvalidAlgorithmParameterException {
    if (cipherAlg == null) {
      throw new IllegalArgumentException("Cannot infer MAC algorithm from cipher algorithm null");
    }

    /*
     * NOTE: AESCMAC will generate 128 bit (16 byte) results, not 64 bit (8 byte),
     * both authentication token generation and secure messaging,
     * where the Mac is applied, will copy only the first 8 bytes.
     */
    if (cipherAlg.startsWith("DESede")) {
      /* NOTE: Some options to be considered here:
       *  - "DESedeMac" (not sure if similar to any of the below options)
       *  - "ISO9797Alg3Mac" (the same we use for BAC based secure messaging)
       *  - "ISO9797ALG3WITHISO7816-4PADDING" (this one was suggested Michal Iwanicki of Decatur Ltd. Thanks!)
       */
      return "ISO9797ALG3WITHISO7816-4PADDING";
    } else if (cipherAlg.startsWith("AES")) {
      return "AESCMAC";
    } else {
      throw new InvalidAlgorithmParameterException("Cannot infer MAC algorithm from cipher algorithm \"" + cipherAlg + "\"");
    }
  }
}
