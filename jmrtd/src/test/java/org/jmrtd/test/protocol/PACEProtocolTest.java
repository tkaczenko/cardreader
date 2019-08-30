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
 * $Id: PACEProtocolTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.protocol;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jmrtd.Util;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.PACEInfo.DHCParameterSpec;
import org.jmrtd.protocol.PACEGMWithECDHAgreement;
import org.jmrtd.protocol.PACEProtocol;

import junit.framework.TestCase;
import net.sf.scuba.util.Hex;

public class PACEProtocolTest extends TestCase {

  private static final Provider BC_PROVIDER = Util.getBouncyCastleProvider();

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  //	PARAM_ID_GFP_1024_160 = 0,
  //	PARAM_ID_GFP_2048_224 = 1,
  //	PARAM_ID_GFP_2048_256 = 2,
  //	/* RFU 3 - 7 */
  //	PARAM_ID_ECP_NIST_P192_R1 = 8,
  //	PARAM_ID_ECP_BRAINPOOL_P192_R1 = 9,
  //	PARAM_ID_ECP_NIST_P224_R1 = 10,
  //	PARAM_ID_ECP_BRAINPOOL_P224_R1 = 11,
  //	PARAM_ID_ECP_NST_P256_R1 = 12,
  //	PARAM_ID_ECP_BRAINPOOL_P256_R1 = 13,
  //	PARAM_ID_ECP_BRAINPOOL_P320_R1 = 14,
  //	PARAM_ID_ECP_NIST_P384_R1 = 15,
  //	PARAM_ID_ECP_BRAINPOOL_P384_R1 = 16,
  //	PARAM_ID_ECP_BRAINPOOL_P512_R1 = 17,
  //	PARAM_ID_ECP_NIST_P512_R1 = 18;

  public void testMacs() {
    try {
      Mac macDESede = Mac.getInstance("DESedeMac", BC_PROVIDER);
      Mac macAES = Mac.getInstance("AESCMAC", BC_PROVIDER);
    } catch(Exception e) {
      fail(e.getMessage());
    }
  }

  public void testPoint() {
    try {
      byte[] paceInfoBytes = Hex.hexStringToBytes("3012060A 04007F00 07020204 02020201 0202010D");
      PACEInfo paceInfo = PACEInfo.createPACEInfo(paceInfoBytes);
      BigInteger paramId = paceInfo.getParameterId();
      assertNotNull(paramId);
      String oid = paceInfo.getObjectIdentifier();
      AlgorithmParameterSpec params = PACEInfo.toParameterSpec(paramId);
      paceInfo.getObjectIdentifier();
      ECPoint publicKeyPoint = new ECPoint(
          Util.os2i(Hex.hexStringToBytes("2DB7A64C 0355044E C9DF1905 14C625CB A2CEA487 54887122 F3A5EF0D 5EDD301C")),
          Util.os2i(Hex.hexStringToBytes("3556F3B3 B186DF10 B857B58F 6A7EB80F 20BA5DC7 BE1D43D9 BF850149 FBB36462")));
      KeyFactory keyFactory  = KeyFactory.getInstance("EC");
      PublicKey publicKey = keyFactory.generatePublic(new ECPublicKeySpec(publicKeyPoint, (ECParameterSpec)params));

      byte[] encodedPublicKeyForSmartCard = PACEProtocol.encodePublicKeyForSmartCard(publicKey);
//      LOGGER.info("DEBUG: encoded public key for smart card = \n" + Hex.bytesToPrettyString(encodedPublicKeyForSmartCard));

      byte[] encodedPublicKeyForMac = PACEProtocol.encodePublicKeyDataObject(oid, publicKey);
//      LOGGER.info("DEBUG: encoded public key for MAC = \n" + Hex.bytesToPrettyString(encodedPublicKeyForMac));

    } catch(Exception e) {
      fail(e.getMessage());
    }
  }

  /**
   * G.1.1. ECDH based example
   *
   * This example is based on ECDH applying the standardized BrainpoolP256r1 domain parameters
   * (see RFC 5639).
   */
  public void testSupplementSampleECDHGM() {
    //    Security.insertProviderAt(BC_PROVIDER, 4);
    try {

      String serialNumber = "T22000129"; /* Check digit 3 */
      String dateOfBirth = "640812"; /* Check digit 5 */
      String dateOfExpiry = "101031"; /* Check digit 8 */
      byte[] paceInfoBytes = Hex.hexStringToBytes("3012060A 04007F00 07020204 02020201 0202010D");

      PACEInfo paceInfo = PACEInfo.createPACEInfo(paceInfoBytes);
      assertNotNull(paceInfo);
      BigInteger paramId = paceInfo.getParameterId();
      String oid = paceInfo.getObjectIdentifier();

      assertEquals("0.4.0.127.0.7.2.2.4.2.2", oid);
      assertEquals(PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, oid);

      assertEquals(BigInteger.valueOf(13), paramId);
      assertEquals(PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1, paramId.intValue());

      AlgorithmParameterSpec params = PACEInfo.toParameterSpec(paramId);
      assertTrue(params instanceof ECParameterSpec);
      ECParameterSpec ecParams = (ECParameterSpec)params;
      KeyFactory keyFactory = KeyFactory.getInstance("EC", BC_PROVIDER);

      String cipherAlg = PACEInfo.toCipherAlgorithm(oid);
      assertEquals(cipherAlg, "AES");
      String digestAlg = PACEInfo.toDigestAlgorithm(oid);
      assertEquals(digestAlg, "SHA-1");
      int keyLength = PACEInfo.toKeyLength(oid);
      assertEquals(keyLength, 128);

      /* Given */
      byte[] expectedKeySeed = Hex.hexStringToBytes("7E2D2A41 C74EA0B3 8CD36F86 3939BFA8 E9032AAD");
      byte[] expectedEncodedSecretKey = Hex.hexStringToBytes("89DED1B2 6624EC1E 634C1989 302849DD");

      /* FIXME: SHA-1 hardcoded here? */
      byte[] keySeed = Util.computeKeySeed(serialNumber, dateOfBirth, dateOfExpiry, "SHA-1", false);
//      LOGGER.info("DEBUG: keySeed = " + Hex.bytesToHexString(keySeed));
      assertTrue(Arrays.equals(expectedKeySeed, keySeed));
      SecretKey secretKey = Util.deriveKey(keySeed, cipherAlg, keyLength, Util.PACE_MODE);
//      LOGGER.info("DEBUG: secretKey = " + Hex.bytesToHexString(secretKey.getEncoded()));
      assertTrue(Arrays.equals(expectedEncodedSecretKey, secretKey.getEncoded()));

      /*
       * Encrypted Nonce.
       *
       * Next, the chip randomly generates the nonce s and encrypts it by means of K_pi.
       */

      /* Given in example. */
      byte[] nonceS = Hex.hexStringToBytes("3F00C4D3 9D153F2B 2A214A07 8D899B22");

      /*
       * Map nonce.
       *
       * The nonce is mapped to an ephemeral group generator via generic mapping. The required randomly chosen
       * ephemeral keys are also collected in the next table.
       */

      /* Terminal's Private Key. */
      BigInteger pcdMappingPrivateKeyFieldElement = Util.os2i(Hex.hexStringToBytes("7F4EF07B 9EA82FD7 8AD689B3 8D0BC78C F21F249D 953BC46F 4C6E1925 9C010F99"));
      PrivateKey pcdMappingPrivateKey = keyFactory.generatePrivate(new ECPrivateKeySpec(pcdMappingPrivateKeyFieldElement, ecParams));

      /* Terminal's Public Key. */
      ECPoint pcdMappingPublicKeyECPoint = new ECPoint(
          Util.os2i(Hex.hexStringToBytes("7ACF3EFC 982EC455 65A4B155 129EFBC7 4650DCBF A6362D89 6FC70262 E0C2CC5E")),
          Util.os2i(Hex.hexStringToBytes("544552DC B6725218 799115B5 5C9BAA6D 9F6BC3A9 618E70C2 5AF71777 A9C4922D")));
      PublicKey pcdMappingPublicKey = keyFactory.generatePublic(new ECPublicKeySpec(pcdMappingPublicKeyECPoint, ecParams));

      /* Chip's Private Key. */
      BigInteger piccMappingPrivateKeyFieldElement = Util.os2i(Hex.hexStringToBytes("498FF497 56F2DC15 87840041 839A8598 2BE7761D 14715FB0 91EFA7BC E9058560"));
      PrivateKey piccMappingPrivateKey = keyFactory.generatePrivate(new ECPrivateKeySpec(piccMappingPrivateKeyFieldElement, ecParams));

      /* Chip's Public Key. */
      ECPoint piccMappingPublicKeyECPoint = new ECPoint(
          Util.os2i(Hex.hexStringToBytes("824FBA91 C9CBE26B EF53A0EB E7342A3B F178CEA9 F45DE0B7 0AA60165 1FBA3F57")),
          Util.os2i(Hex.hexStringToBytes("30D8C879 AAA9C9F7 3991E61B 58F4D52E B87A0A0C 709A49DC 63719363 CCD13C54")));
      PublicKey piccMappingPublicKey = keyFactory.generatePublic(new ECPublicKeySpec(piccMappingPublicKeyECPoint, ecParams));

      /* Given in example. */
      ECPoint expectedSharedSecretECPointH = new ECPoint(
          Util.os2i(Hex.hexStringToBytes("60332EF2 450B5D24 7EF6D386 8397D398 852ED6E8 CAF6FFEE F6BF85CA 57057FD5")),
          Util.os2i(Hex.hexStringToBytes("0840CA74 15BAF3E4 3BD414D3 5AA4608B 93A2CAF3 A4E3EA4E 82C9C13D 03EB7181")));

      //      KeyAgreement mappingAgreement = KeyAgreement.getInstance("ECDH");
      //      mappingAgreement.init(pcdMappingPrivateKey);
      //
      //      mappingAgreement.doPhase(piccMappingPublicKey, true);
      //      byte[] sharedSecretH = mappingAgreement.generateSecret();

      PACEGMWithECDHAgreement mappingAgreement = new PACEGMWithECDHAgreement();
      mappingAgreement.init(pcdMappingPrivateKey);
      ECPoint sharedSecretH = mappingAgreement.doPhase(PACEProtocol.updateParameterSpec(piccMappingPublicKey, pcdMappingPrivateKey));


      ECParameterSpec ephemeralParams = (ECParameterSpec)PACEProtocol.mapNonceGMWithECDH(nonceS, sharedSecretH, ecParams);

      KeyPairGenerator keyPairGenerator = null;
      KeyPair kp = null;
      PrivateKey pcdPrivateKey = null;
      KeyAgreement keyAgreement = null;

      keyPairGenerator = KeyPairGenerator.getInstance("EC", BC_PROVIDER);
      keyPairGenerator.initialize(ephemeralParams);
      kp = keyPairGenerator.generateKeyPair();
      pcdPrivateKey = kp.getPrivate();

      keyAgreement = KeyAgreement.getInstance("ECDH", BC_PROVIDER);
      keyAgreement.init(pcdPrivateKey);

      keyAgreement.doPhase(PACEProtocol.updateParameterSpec(piccMappingPublicKey, pcdPrivateKey), true);

      byte[] generatedSharedSecretBytesH = keyAgreement.generateSecret();

      /* Given in example. */
      byte[] expectedEphemeralGeneratorX = Hex.hexStringToBytes("8CED63C9 1426D4F0 EB1435E7 CB1D74A4 6723A0AF 21C89634 F65A9AE8 7A9265E2");
      byte[] expectedEphemeralGeneratorY = Hex.hexStringToBytes("8C879506 743F8611 AC33645C 5B985C80 B5F09A0B 83407C1B 6A4D857A E76FE522");

      BigInteger s = Util.os2i(nonceS);

      ECParameterSpec ephemeralECParams = (ECParameterSpec)PACEProtocol.mapNonceGMWithECDH(nonceS, sharedSecretH, ecParams);

      ECPoint ephemeralGenerator = ephemeralECParams.getGenerator();
      byte[] ephemeralGeneratorX = Util.i2os(ephemeralGenerator.getAffineX());
      byte[] ephemeralGeneratorY = Util.i2os(ephemeralGenerator.getAffineY());

      assertTrue(Arrays.equals(expectedEphemeralGeneratorX, ephemeralGeneratorX));
      assertTrue(Arrays.equals(expectedEphemeralGeneratorY, ephemeralGeneratorY));

      /*
       * Perform Key Agreement.
       *
       * In the third step, chip and terminal perform an anonymous ECDH key agreement using the new domain
       * parameters determined by the ephemeral group generator G~ of the previous step. According to the Technical
       * Report SAC, only the x-coordinate is required as shared secret since the KDF only uses the first coordinate to
       * derive the session keys.
       */
      BigInteger p = Util.getPrime(ephemeralParams);

      BigInteger pcdPrivateKeyFieldElement = Util.os2i(Hex.hexStringToBytes("A73FB703 AC1436A1 8E0CFA5A BB3F7BEC 7A070E7A 6788486B EE230C4A 22762595"));
      ECPoint pcdPublicKeyPoint = new ECPoint(
          Util.os2i(Hex.hexStringToBytes("2DB7A64C 0355044E C9DF1905 14C625CB A2CEA487 54887122 F3A5EF0D 5EDD301C")),
          Util.os2i(Hex.hexStringToBytes("3556F3B3 B186DF10 B857B58F 6A7EB80F 20BA5DC7 BE1D43D9 BF850149 FBB36462")));
      ECPoint piccPublicKeyPoint = new ECPoint(
          Util.os2i(Hex.hexStringToBytes("9E880F84 2905B8B3 181F7AF7 CAA9F0EF B743847F 44A306D2 D28C1D9E C65DF6DB")),
          Util.os2i(Hex.hexStringToBytes("7764B222 77A2EDDC 3C265A9F 018F9CB8 52E111B7 68B32690 4B59A019 3776F094")));

      /* Given in example. */
      byte[] expectedSharedSecret = Hex.hexStringToBytes("28768D20 701247DA E81804C9 E780EDE5 82A9996D B4A31502 0B273319 7DB84925");
//      LOGGER.info("DEBUG: expectedSharedSecret.length = " + expectedSharedSecret.length);

      keyFactory = KeyFactory.getInstance("EC", BC_PROVIDER);
      pcdPrivateKey = keyFactory.generatePrivate(new ECPrivateKeySpec(pcdPrivateKeyFieldElement, ephemeralECParams));
      PublicKey pcdPublicKey = keyFactory.generatePublic(new ECPublicKeySpec(pcdPublicKeyPoint, ephemeralECParams));
      PublicKey piccPublicKey = keyFactory.generatePublic(new ECPublicKeySpec(piccPublicKeyPoint, ephemeralECParams));

      keyAgreement = KeyAgreement.getInstance("ECDH", BC_PROVIDER);
      assertNotNull(keyAgreement);
      keyAgreement.init(pcdPrivateKey);

      if (pcdPublicKey.equals(piccPublicKey)) {
        throw new GeneralSecurityException("pcdPublicKey and piccPublicKey are the same!");
      }
      keyAgreement.doPhase(piccPublicKey, true);
      byte[] sharedSecretBytes = keyAgreement.generateSecret();
      assertNotNull(sharedSecretBytes);

      assertTrue(Arrays.equals(expectedSharedSecret, sharedSecretBytes));

      /*
       * Derive secure messaging keys.
       */

      /* Given in example. */
      byte[] expectedEncKeyBytes = Hex.hexStringToBytes("F5F0E35C 0D7161EE 6724EE51 3A0D9A7F");
      byte[] expectedMacKeyBytes = Hex.hexStringToBytes("FE251C78 58B356B2 4514B3BD 5F4297D1");

      SecretKey encKey = null;
      SecretKey macKey = null;
      try {
//        LOGGER.info("DEBUG: digestAlg = " + digestAlg);

        encKey = Util.deriveKey(sharedSecretBytes, cipherAlg, keyLength, Util.ENC_MODE);
        byte[] encKeyBytes = encKey.getEncoded();
        assertTrue(Arrays.equals(expectedEncKeyBytes, encKeyBytes));

        macKey = Util.deriveKey(sharedSecretBytes, cipherAlg, keyLength, Util.MAC_MODE);
        byte[] macKeyBytes = macKey.getEncoded();
        assertTrue(Arrays.equals(expectedMacKeyBytes, macKeyBytes));
      } catch (GeneralSecurityException gse) {
        LOGGER.log(Level.WARNING, "Unexpected security exception", gse);
        throw new IllegalStateException(gse.getMessage());
      }

      /*
       * Mutual authentication.
       */
      byte[] expectedInputDataForPCDToken = Hex.hexStringToBytes("7F494F06 0A04007F 00070202 04020286"
          + "41049E88 0F842905 B8B3181F 7AF7CAA9"
          + "F0EFB743 847F44A3 06D2D28C 1D9EC65D"
          + "F6DB7764 B22277A2 EDDC3C26 5A9F018F"
          + "9CB852E1 11B768B3 26904B59 A0193776"
          + "F094");
      byte[] expectedInputDataForPICCToken = Hex.hexStringToBytes("7F494F06 0A04007F 00070202 04020286"
          + "41042DB7 A64C0355 044EC9DF 190514C6"
          + "25CBA2CE A4875488 7122F3A5 EF0D5EDD"
          + "301C3556 F3B3B186 DF10B857 B58F6A7E"
          + "B80F20BA 5DC7BE1D 43D9BF85 0149FBB3"
          + "6462");

      byte[] encodedPCDPublicKeyDataObject = PACEProtocol.encodePublicKeyDataObject(oid, pcdPublicKey);

//      LOGGER.info("DEBUG: expectedInputDataForPICCToken = " + Hex.bytesToHexString(expectedInputDataForPICCToken));
//      LOGGER.info("DEBUG: encodedPCDPublicKeyDataObject = " + Hex.bytesToHexString(encodedPCDPublicKeyDataObject));

      assertTrue(Arrays.equals(expectedInputDataForPICCToken, encodedPCDPublicKeyDataObject));

      byte[] encodedPICCPublicKeyDataObject = PACEProtocol.encodePublicKeyDataObject(oid, piccPublicKey);
      assertTrue(Arrays.equals(expectedInputDataForPCDToken, encodedPICCPublicKeyDataObject));

      /* Given in example. */
      byte[] expectedPCDAuthenticationToken = Hex.hexStringToBytes("C2B0BD78 D94BA866");
      byte[] expectedPICCAuthenticationToken = Hex.hexStringToBytes("3ABB9674 BCE93C08");

      byte[] pcdToken = PACEProtocol.generateAuthenticationToken(oid, macKey, piccPublicKey);
      byte[] piccToken =  PACEProtocol.generateAuthenticationToken(oid, macKey, pcdPublicKey);

      assertTrue(Arrays.equals(expectedPCDAuthenticationToken, pcdToken));
      assertTrue(Arrays.equals(expectedPICCAuthenticationToken, piccToken));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  private boolean equals(ECParameterSpec ecParams1, ECParameterSpec ecParams2) {

    if (ecParams1.getCofactor() != ecParams2.getCofactor()) {
      return false;
    }

    if (!curveToString(ecParams1).equals(curveToString(ecParams2))) {
      return false;
    }

    return true;
  }

  private String toString(ECParameterSpec params) {
    StringBuilder result = new StringBuilder();
    result.append("ECParameterSpec[");
    result.append("Generator: " + toString(params.getGenerator()));
    result.append(", Co-factor: " + params.getCofactor());
    result.append(", Curve: " + curveToString(params));
    result.append("]");
    return result.toString();
  }

  private String toString(ECPoint ecPoint) {
    return "(" + ecPoint.getAffineX() + ", " + ecPoint.getAffineY() + ")";
  }

  private String curveToString(ECParameterSpec params) {
    String curveName = Util.getCurveName(params);

    if (curveName != null) {
      return "EllipticCurve [" + curveName + "]";
    }

    EllipticCurve curve = params.getCurve();

    StringBuilder result = new StringBuilder();

    ECField field = curve.getField();
    if (field instanceof ECFieldFp) {
      ECFieldFp fieldFp = (ECFieldFp)field;
      result.append("Prime field with prime " + fieldFp.getP());
    } else if (field instanceof ECFieldF2m) {
      ECFieldF2m fieldF2m = (ECFieldF2m)field;
      return "Binary field with exponent " + fieldF2m.getM();
    } else {
      result.append("Unknown field of size " + field.getFieldSize());
    }
    result.append(", A: " + curve.getA());
    result.append(", B: " + curve.getB());
    result.append("]");
    return result.toString();
  }

  public void testMultiplicationWithEphemeralParams(ECParameterSpec params) {
    ECPoint Q = Util.multiply(BigInteger.ONE, params.getGenerator(), params);
  }

  public void testSupplementDHGMSample() {
    /*
     * G.1.2. DH based example
     *
     * The second example is based on DH using the 1024-bit MODP Group with 160-bit Prime Order Subgroup
     * specified by RFC 5114. The example is taken from the EAC 2 worked example (BSI 2010), making minor
     * modifications.
     */

    try {
      /* Input. Given in example. */
      byte[] paceInfoBytes = Hex.hexStringToBytes("3012060A 04007F00 07020204 01020201 02020100");

      /* Input. Given in example. */
      byte[] nonceSBytes = Hex.hexStringToBytes("FA5B7E3E 49753A0D B9178B7B 9BD898C8");

      /* Input. Given in example. */
      byte[] sharedSecretHBytes = Hex.hexStringToBytes(
          "5BABEBEF 5B74E5BA 94B5C063 FDA15F1F"
              + "1CDE9487 3EE0A5D3 A2FCAB49 F258D07F"
              + "544F13CB 66658C3A FEE9E727 389BE3F6"
              + "CBBBD321 28A8C21D D6EEA3CF 7091CDDF"
              + "B08B8D00 7D40318D CCA4FFBF 51208790"
              + "FB4BD111 E5A968ED 6B6F08B2 6CA87C41"
              + "0B3CE0C3 10CE104E ABD16629 AA48620C"
              + "1279270C B0750C0D 37C57FFF E302AE7F");

      /* Output. Given in example. */
      byte[] expectedEphemeralGeneratorBytes = Hex.hexStringToBytes(
          "7C9CBFE9 8F9FBDDA 8D143506 FA7D9306"
              + "F4CB17E3 C71707AF F5E1C1A1 23702496"
              + "84D64EE3 7AF44B8D BD9D45BF 6023919C"
              + "BAA027AB 97ACC771 666C8E98 FF483301"
              + "BFA4872D EDE9034E DFACB708 14166B7F"
              + "36067682 9B826BEA 57291B5A D69FBC84"
              + "EF1E7790 32A30580 3F743417 93E86974"
              + "2D401325 B37EE856 5FFCDEE6 18342DC5");

      PACEInfo paceInfo = PACEInfo.createPACEInfo(paceInfoBytes);
      assertNotNull(paceInfo);

      String oid = paceInfo.getObjectIdentifier();
      assertEquals(oid, PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128); // id-PACE-DH-GM-AES-CBC-CMAC-128
      String cipherAlg = PACEInfo.toCipherAlgorithm(oid);
      assertEquals("AES", cipherAlg);
      String digestAlg = PACEInfo.toDigestAlgorithm(oid);
      assertEquals("SHA-1", digestAlg);
      int keyLength = PACEInfo.toKeyLength(oid);
      assertEquals(128, keyLength);
      String agreementAlg = PACEInfo.toKeyAgreementAlgorithm(oid);
      assertEquals("DH", agreementAlg);

      AlgorithmParameterSpec params = PACEInfo.toParameterSpec(paceInfo.getParameterId());
      assertTrue(params instanceof DHParameterSpec);

      DHParameterSpec dhParams = (DHParameterSpec)params;

      BigInteger nonceS = Util.os2i(nonceSBytes);

      BigInteger sharedSecretH = Util.os2i(sharedSecretHBytes);

      AlgorithmParameterSpec ephemeralParams = PACEProtocol.mapNonceGMWithDH(nonceSBytes, Util.os2i(sharedSecretHBytes), dhParams);
      assertTrue(ephemeralParams instanceof DHParameterSpec);
      DHParameterSpec ephemeralDHParams = (DHParameterSpec)ephemeralParams;

      BigInteger ephemeralGenerator = ephemeralDHParams.getG();
      byte[] ephemeralGeneratorBytes = Util.i2os(ephemeralGenerator);
      assertTrue(Arrays.equals(expectedEphemeralGeneratorBytes, ephemeralGeneratorBytes));

      /*
       * Key agreement.
       */
      BigInteger p = Util.getPrime(ephemeralParams);
      KeyFactory keyFactory = KeyFactory.getInstance("DH", BC_PROVIDER);

      BigInteger pcdPrivateKeyFieldElement = Util.os2i(Hex.hexStringToBytes("4BD0E547 40F9A028 E6A515BF DAF96784"
          + "8C4F5F5F FF65AA09 15947FFD 1A0DF2FA"
          + "6981271B C905F355 1457B7E0 3AC3B806"
          + "6DE4AA40 6C1171FB 43DD939C 4BA16175"
          + "103BA3DE E16419AA 248118F9 0CC36A3D"
          + "6F4C3736 52E0C3CC E7F0F1D0 C5425B36"
          + "00F0F0D6 A67F004C 8BBA33F2 B4733C72"
          + "52445C1D FC4F1107 203F71D2 EFB28161"));
      BigInteger pcdPublicKeyFieldElement = Util.os2i(Hex.hexStringToBytes("00907D89 E2D425A1 78AA81AF 4A7774EC"
          + "8E388C11 5CAE6703 1E85EECE 520BD911"
          + "551B9AE4 D04369F2 9A02626C 86FBC674"
          + "7CC7BC35 2645B616 1A2A42D4 4EDA80A0"
          + "8FA8D61B 76D3A154 AD8A5A51 786B0BC0"
          + "71470578 71A92221 2C5F67F4 31731722"
          + "36B7747D 1671E6D6 92A3C7D4 0A0C3C5C"
          + "E397545D 015C175E B5130551 EDBC2EE5 D4"));
      BigInteger piccPublicKeyFieldElement = Util.os2i(Hex.hexStringToBytes("075693D9 AE941877 573E634B 6E644F8E"
          + "60AF17A0 076B8B12 3D920107 4D36152B"
          + "D8B3A213 F53820C4 2ADC79AB 5D0AEEC3"
          + "AEFB9139 4DA476BD 97B9B14D 0A65C1FC"
          + "71A0E019 CB08AF55 E1F72900 5FBA7E3F"
          + "A5DC4189 9238A250 767A6D46 DB974064"
          + "386CD456 743585F8 E5D90CC8 B4004B1F"
          + "6D866C79 CE0584E4 9687FF61 BC29AEA1"));

      /* Given in example. */
      byte[] expectedSharedSecret = Hex.hexStringToBytes("6BABC7B3 A72BCD7E A385E4C6 2DB2625B"
          + "D8613B24 149E146A 629311C4 CA6698E3"
          + "8B834B6A 9E9CD718 4BA8834A FF5043D4"
          + "36950C4C 1E783236 7C10CB8C 314D40E5"
          + "990B0DF7 013E64B4 549E2270 923D06F0"
          + "8CFF6BD3 E977DDE6 ABE4C31D 55C0FA2E"
          + "465E553E 77BDF75E 3193D383 4FC26E8E"
          + "B1EE2FA1 E4FC97C1 8C3F6CFF FE2607FD");

      PrivateKey pcdPrivateKey = keyFactory.generatePrivate(new DHPrivateKeySpec(pcdPrivateKeyFieldElement, p, ephemeralGenerator));
      PublicKey pcdPublicKey = keyFactory.generatePublic(new DHPublicKeySpec(pcdPublicKeyFieldElement, p, ephemeralGenerator));
      PublicKey piccPublicKey = keyFactory.generatePublic(new DHPublicKeySpec(piccPublicKeyFieldElement, p, ephemeralGenerator));

      KeyAgreement keyAgreement = KeyAgreement.getInstance("DH", BC_PROVIDER);
      assertNotNull(keyAgreement);
      keyAgreement.init(pcdPrivateKey);

      if (pcdPublicKey.equals(piccPublicKey)) {
        throw new GeneralSecurityException("pcdPublicKey and piccPublicKey are the same!");
      }
      keyAgreement.doPhase(piccPublicKey, true);
      byte[] sharedSecretBytes = keyAgreement.generateSecret();
      assertNotNull(sharedSecretBytes);

      assertTrue(Arrays.equals(expectedSharedSecret, sharedSecretBytes));

      /*
       * Derive secure messaging keys.
       */

      /* Given in example. */
      byte[] expectedEncKeyBytes = Hex.hexStringToBytes("2F7F46AD CC9E7E52 1B45D192 FAFA9126");
      byte[] expectedMacKeyBytes = Hex.hexStringToBytes("805A1D27 D45A5116 F73C5446 9462B7D8");

      SecretKey encKey = Util.deriveKey(sharedSecretBytes, cipherAlg, keyLength, Util.ENC_MODE);
      byte[] encKeyBytes = encKey.getEncoded();
      assertTrue(Arrays.equals(expectedEncKeyBytes, encKeyBytes));

      SecretKey macKey = Util.deriveKey(sharedSecretBytes, cipherAlg, keyLength, Util.MAC_MODE);
      byte[] macKeyBytes = macKey.getEncoded();
      assertTrue(Arrays.equals(expectedMacKeyBytes, macKeyBytes));

      /*
       * Mutual authentication.
       */
      byte[] expectedInputDataForPCDToken = Hex.hexStringToBytes("7F49818F 060A0400 7F000702 02040102"
          + "84818007 5693D9AE 94187757 3E634B6E"
          + "644F8E60 AF17A007 6B8B123D 9201074D"
          + "36152BD8 B3A213F5 3820C42A DC79AB5D"
          + "0AEEC3AE FB91394D A476BD97 B9B14D0A"
          + "65C1FC71 A0E019CB 08AF55E1 F729005F"
          + "BA7E3FA5 DC418992 38A25076 7A6D46DB"
          + "97406438 6CD45674 3585F8E5 D90CC8B4"
          + "004B1F6D 866C79CE 0584E496 87FF61BC"
          + "29AEA1");
      byte[] expectedInputDataForPICCToken = Hex.hexStringToBytes("7F49818F 060A0400 7F000702 02040102"
          + "84818090 7D89E2D4 25A178AA 81AF4A77"
          + "74EC8E38 8C115CAE 67031E85 EECE520B"
          + "D911551B 9AE4D043 69F29A02 626C86FB"
          + "C6747CC7 BC352645 B6161A2A 42D44EDA"
          + "80A08FA8 D61B76D3 A154AD8A 5A51786B"
          + "0BC07147 057871A9 22212C5F 67F43173"
          + "172236B7 747D1671 E6D692A3 C7D40A0C"
          + "3C5CE397 545D015C 175EB513 0551EDBC"
          + "2EE5D4");

      byte[] encodedPCDPublicKeyDataObject = PACEProtocol.encodePublicKeyDataObject(oid, pcdPublicKey);
      assertTrue(Arrays.equals(expectedInputDataForPICCToken, encodedPCDPublicKeyDataObject));

      byte[] encodedPICCPublicKeyDataObject = PACEProtocol.encodePublicKeyDataObject(oid, piccPublicKey);
      assertTrue(Arrays.equals(expectedInputDataForPCDToken, encodedPICCPublicKeyDataObject));

      /* Given in example. */
      byte[] expectedPCDAuthenticationToken = Hex.hexStringToBytes("B46DD9BD 4D98381F");
      byte[] expectedPICCAuthenticationToken = Hex.hexStringToBytes("917F37B5 C0E6D8D1");

      byte[] pcdAuthenticationToken = PACEProtocol.generateAuthenticationToken(oid, macKey, piccPublicKey);
      byte[] piccAuthenticationToken =  PACEProtocol.generateAuthenticationToken(oid, macKey, pcdPublicKey);

      assertTrue(Arrays.equals(expectedPCDAuthenticationToken, pcdAuthenticationToken));
      assertTrue(Arrays.equals(expectedPICCAuthenticationToken, piccAuthenticationToken));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testDutch2014PassportWithGMAndECDH() {
    try {
      String oid = "0.4.0.127.0.7.2.2.4.2.4"; // id-PACE-ECDH-GM-AES-CBC-CMAC-256
      assertEquals(oid, PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256);

      int version = 2;
      int paramId = 14;
      PACEInfo paceInfo = new PACEInfo(oid, version, paramId);

      String cipherAlg = PACEInfo.toCipherAlgorithm(oid);
      assertEquals("AES", cipherAlg);
      String digestAlg = PACEInfo.toDigestAlgorithm(oid);
      assertEquals("SHA-256", digestAlg);
      int keyLength = PACEInfo.toKeyLength(oid);
      assertEquals(256, keyLength);
      String agreementAlg = PACEInfo.toKeyAgreementAlgorithm(oid);
      assertEquals("ECDH", agreementAlg);

      AlgorithmParameterSpec params = PACEInfo.toParameterSpec(paceInfo.getParameterId());
      assertTrue(params instanceof ECParameterSpec);

      ECParameterSpec ecParams = (ECParameterSpec)params;
      BigInteger p = Util.getPrime(ecParams);

      byte[] nonceS = Hex.hexStringToBytes("1BBF56756A0C1E74AE3524685D970724");

      BigInteger pcdMappingPrivateKeyFieldElement = Util.os2i(Hex.hexStringToBytes("CFE032E195BC18D1B6C7F5C137CF9FDA52ECACF04A066839022AC1AF686AB3AA2102E9C918624262"));

      byte[] piccMappingEncodedPublicKey = Hex.hexStringToBytes("04"
          + "AED562971B07877839B064B39132394E79CEF2BED81D8907B539030FB85D1D45EEA9788F28280629"
          + "53C25E414F44CA391C633FFA9983C0EC05C895636A4B2B44B446848FE57E9F8587B0202CFF4BE70E");

      KeyFactory keyFactory = KeyFactory.getInstance("EC", BC_PROVIDER);
      PrivateKey pcdMappingPrivateKey = keyFactory.generatePrivate(new ECPrivateKeySpec(pcdMappingPrivateKeyFieldElement, ecParams));
      //			PublicKey piccMappingPublicKey = keyFactory.generatePublic(new ECPublicKeySpec(piccMappingPublicKeyPoint, ecParams));
      PublicKey piccMappingPublicKey = PACEProtocol.decodePublicKeyFromSmartCard(piccMappingEncodedPublicKey, params);

      PACEGMWithECDHAgreement mappingAgreement = new PACEGMWithECDHAgreement();
      mappingAgreement.init(pcdMappingPrivateKey);
      ECPoint mappingSharedSecret = mappingAgreement.doPhase(PACEProtocol.updateParameterSpec(piccMappingPublicKey, pcdMappingPrivateKey));

//      LOGGER.info("DEBUG: mappingSharedSecret = " + mappingSharedSecret);

      ECParameterSpec ephemeralParams = PACEProtocol.mapNonceGMWithECDH(nonceS, mappingSharedSecret, ecParams);

      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BC_PROVIDER);
      keyPairGenerator.initialize(ephemeralParams);
      KeyPair kp = keyPairGenerator.generateKeyPair();
      PrivateKey pcdPrivateKey = kp.getPrivate();
      KeyAgreement keyAgreement = KeyAgreement.getInstance(agreementAlg);
      keyAgreement.init(pcdPrivateKey);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }

  /**
   * Example from
   * Appendix H to Part 11: Worked Example: PACE - Integrated Mapping (Informative).
   *
   * This example is based on the BrainpoolP256r1 elliptic curve.
   * The block cipher used in this example is AES-128.
   */
  /*
   * Pseudorandom R(s,t) =
   *    E4447E2D FB3586BA C05DDB00 156B57FB
   *    B2179A39 49294C97 25418980 0C517BAA
   *    8DA0FF39 7ED8C445 D3E421E4 FEB57322
   *
   * Expected R_p(s,t) =
   *    A2F8FF2D F50E52C6 599F386A DCB595D2
   *    29F6A167 ADE2BE5F 2C3296AD D5B7430E
   */
  public void testPseudoRandomFunctionWorkedExampleH1() {
    try {
      ECParameterSpec params = (ECParameterSpec)PACEInfo.toParameterSpec(PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1);
      BigInteger p = Util.getPrime(params);
      byte[] s = Hex.hexStringToBytes("2923BE84 E16CD6AE 529049F1 F1BBE9EB");
      byte[] t = Hex.hexStringToBytes("5DD4CBFC 96F5453B 130D890A 1CDBAE32");

      byte[] expectedX = Hex.hexStringToBytes("A2F8FF2D F50E52C6 599F386A DCB595D2" + "29F6A167 ADE2BE5F 2C3296AD D5B7430E");

      byte[] x = PACEProtocol.pseudoRandomFunction(s, t, p, "AES");

      assertTrue(Arrays.equals(expectedX, x));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }

  /**
   * Example from
   * Appendix H to Part 11: Worked Example: PACE - Integrated Mapping (Informative).
   *
   * This example is based on the BrainpoolP256r1 elliptic curve.
   */
  public void testSpecSamplePACEIMWithECDHPointEncodingExampleH1() {
    try {
      byte[] expectedMappedGeneratorX = Hex.hexStringToBytes("8E82D315 59ED0FDE 92A4D049 8ADD3C23"
          + "BABA94FB 77691E31 E90AEA77 FB17D427");

      byte[] expectedMappedGeneratorY = Hex.hexStringToBytes("4C1AE14B D0C3DBAC 0C871B7F 36081693"
          + "64437CA3 0AC243A0 89D3F266 C1E60FAD");

      ECParameterSpec staticParameters = (ECParameterSpec)PACEInfo.toParameterSpec(PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1);

      byte[] decryptedNonceS = Hex.hexStringToBytes("2923BE84 E16CD6AE 529049F1 F1BBE9EB");
      byte[] nonceT = Hex.hexStringToBytes("5DD4CBFC 96F5453B 130D890A 1CDBAE32");

      byte[] pseudRandomFunctionResult = Hex.hexStringToBytes("A2F8FF2D F50E52C6 599F386A DCB595D2"
          + "29F6A167 ADE2BE5F 2C3296AD D5B7430E");

      ECPoint mappedGenerator  = PACEProtocol.icartPointEncode(Util.os2i(pseudRandomFunctionResult), staticParameters);

      assertEquals(Util.os2i(expectedMappedGeneratorX), mappedGenerator.getAffineX());
      assertEquals(Util.os2i(expectedMappedGeneratorY), mappedGenerator.getAffineY());
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  /*
   * Pseudo-random R(s,t) =
   *    EAB98D13 E0905295 2AA72990 7C3C9461
   *    84DEA0FE 74AD2B3A F506F0A8 3018459C
   *    38099CD1 F7FF4EA0 A078DB1F AC136550
   *    5E3DC855 00EF95E2 0B4EEF2E 88489233
   *    BEE0546B 472F994B 618D1687 02406791
   *    DEEF3CB4 810932EC 278F3533 FDB860EB
   *    4835C36F A4F1BF3F A0B828A7 18C96BDE
   *    88FBA38A 3E6C35AA A1095925 1EB5FC71
   *    0FC18725 8995944C 0F926E24 9373F485
   *
   * Rp(s,t) =
   *    A0C7C50C 002061A5 1CC87D25 4EF38068
   *    607417B6 EE1B3647 3CFB800D 2D2E5FA2
   *    B6980F01 105D24FA B22ACD1B FA5C8A4C
   *    093ECDFA FE6D7125 D42A843E 33860383
   *    5CF19AFA FF75EFE2 1DC5F6AA 1F9AE46C
   *    25087E73 68166FB0 8C1E4627 AFED7D93
   *    570417B7 90FF7F74 7E57F432 B04E1236
   *    819E0DFE F5B6E77C A4999925 328182D2
   */
  public void testPACEIMWithDHWorkedExampleH2() {
    try {
      BigInteger p = new BigInteger(("B10B8F96 A080E01D DE92DE5E AE5D54EC"
          + "52C99FBC FB06A3C6 9A6A9DCA 52D23B61"
          + "6073E286 75A23D18 9838EF1E 2EE652C0"
          + "13ECB4AE A9061123 24975C3C D49B83BF"
          + "ACCBDD7D 90C4BD70 98488E9C 219A7372"
          + "4EFFD6FA E5644738 FAA31A4F F55BCCC0"
          + "A151AF5F 0DC8B4BD 45BF37DF 365C1A65"
          + "E68CFDA7 6D4DA708 DF1FB2BC 2E4A4371").replace(" ", ""), 16);

      byte[] s = Hex.hexStringToBytes("FA5B7E3E 49753A0D B9178B7B 9BD898C8");
      byte[] t = Hex.hexStringToBytes("B3A6DB3C 870C3E99 245E0D1C 06B747DE");

      byte[] expectedX = Hex.hexStringToBytes("A0C7C50C 002061A5 1CC87D25 4EF38068"
          + "607417B6 EE1B3647 3CFB800D 2D2E5FA2"
          +" B6980F01 105D24FA B22ACD1B FA5C8A4C"
          + "093ECDFA FE6D7125 D42A843E 33860383"
          + "5CF19AFA FF75EFE2 1DC5F6AA 1F9AE46C"
          + "25087E73 68166FB0 8C1E4627 AFED7D93"
          + "570417B7 90FF7F74 7E57F432 B04E1236"
          + "819E0DFE F5B6E77C A4999925 328182D2");

      byte[] x = PACEProtocol.pseudoRandomFunction(s, t, p, "AES");

      assertTrue(Arrays.equals(expectedX, x));

      BigInteger expectedMappedGenerator = Util.os2i(Hex.hexStringToBytes("1D7D767F 11E333BC D6DBAEF4 0E799E7A"
          + "926B9697 3550656F F3C83072 6D118D61"
          + "C276CDCC 61D475CF 03A98E0C 0E79CAEB"
          + "A5BE2557 8BD4551D 0B109032 36F0B0F9"
          + "76852FA7 8EEA14EA 0ACA87D1 E91F688F"
          + "E0DFF897 BBE35A47 2621D343 564B262F"
          + "34223AE8 FC59B664 BFEDFA2B FE7516CA"
          + "5510A6BB B633D517 EC25D4E0 BBAA16C2"));

      BigInteger g = Util.os2i(Hex.hexStringToBytes("A4D1CBD5 C3FD3412 6765A442 EFB99905"
          + "F8104DD2 58AC507F D6406CFF 14266D31"
          + "266FEA1E 5C41564B 777E690F 5504F213"
          + "160217B4 B01B886A 5E91547F 9E2749F4"
          + "D7FBD7D3 B9A92EE1 909D0D22 63F80A76"
          + "A6A24C08 7A091F53 1DBF0A01 69B6A28A"
          + "D662A4D1 8E73AFA3 2D779D59 18D08BC8"
          + "858F4DCE F97C2A24 855E6EEB 22B3B2E5"));

      BigInteger q = Util.os2i(Hex.hexStringToBytes("F518AA87 81A8DF27 8ABA4E7D 64B7CB9D"
          + "49462353"));

      org.bouncycastle.crypto.params.DHParameters bcParams = new org.bouncycastle.crypto.params.DHParameters(p, g, q);

      DHCParameterSpec params = new DHCParameterSpec(p, g, q);

      DHParameterSpec mappedParams = (DHParameterSpec)PACEProtocol.mapNonceIMWithDH(s, t, "AES", params);

      BigInteger mappedGenerator = mappedParams.getG();

      assertEquals(expectedMappedGenerator, mappedGenerator);

    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }
}
