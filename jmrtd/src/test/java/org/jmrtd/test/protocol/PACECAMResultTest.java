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
 * $Id: PACECAMResultTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.protocol;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.jmrtd.AccessKeySpec;
import org.jmrtd.BACKey;
import org.jmrtd.PACEKeySpec;
import org.jmrtd.PassportService;
import org.jmrtd.Util;
import org.jmrtd.lds.PACEInfo.MappingType;
import org.jmrtd.protocol.AESSecureMessagingWrapper;
import org.jmrtd.protocol.PACECAMResult;
import org.jmrtd.protocol.PACEMappingResult;
import org.jmrtd.protocol.SecureMessagingWrapper;

import junit.framework.TestCase;

public class PACECAMResultTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private static final Provider BC_PROVIDER = Util.getBouncyCastleProvider();

  public void testPACECAMResult() {
    try {
      String documentNumner = "123456789";
      String dateOfBirth = "710121";
      String dateOfExpiry = "331231";
      AccessKeySpec paceKey = PACEKeySpec.createMRZKey(new BACKey(documentNumner, dateOfBirth, dateOfExpiry));
      String agreementAlg = "ECDH";
      String cipherAlg = "AES";
      String digestAlg = "SHA-256";
      int keyLength = 128;
      PACEMappingResult mappingResult = null;

      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", BC_PROVIDER);
      keyPairGenerator.initialize(256);
      KeyPair piccKeyPair = keyPairGenerator.generateKeyPair();
      PublicKey piccPublicKey = piccKeyPair.getPublic();

      KeyPair pcdKeyPair = keyPairGenerator.generateKeyPair();

      SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(getRandomAESKey(), getRandomAESKey(), PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, true, 0L);

      byte[] chipAuthenticationData = new byte[8]; // FIXME: Generate randomly.

      byte[] encryptedChipAuthenticationData = new byte[128]; // FIXME: Encrypt chipAuthenticationData ourselves.

      PACECAMResult paceCAMResult = new PACECAMResult(paceKey, agreementAlg, cipherAlg, digestAlg, keyLength, mappingResult, pcdKeyPair, piccPublicKey, encryptedChipAuthenticationData, chipAuthenticationData, wrapper);

      assertEquals(agreementAlg, paceCAMResult.getAgreementAlg());
      assertEquals(paceKey, paceCAMResult.getPACEKey());

      assertEquals(cipherAlg, paceCAMResult.getCipherAlg());
      assertEquals(digestAlg, paceCAMResult.getDigestAlg());
      assertEquals(keyLength, paceCAMResult.getKeyLength());
      assertEquals(mappingResult, paceCAMResult.getMappingResult());
      assertEquals(MappingType.CAM, paceCAMResult.getMappingType());

      assertEquals(pcdKeyPair, paceCAMResult.getPCDKeyPair());

      assertEquals(piccPublicKey, paceCAMResult.getPICCPublicKey());

      assertTrue(Arrays.equals(encryptedChipAuthenticationData, paceCAMResult.getEncryptedChipAuthenticationData()));
      assertTrue(Arrays.equals(chipAuthenticationData, paceCAMResult.getChipAuthenticationData()));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }

  public void testPACECAMResultEquals() {
    try {
      String documentNumner = "123456789";
      String dateOfBirth = "710121";
      String dateOfExpiry = "331231";
      AccessKeySpec paceKey = PACEKeySpec.createMRZKey(new BACKey(documentNumner, dateOfBirth, dateOfExpiry));
      String agreementAlg = "ECDH";
      String cipherAlg = "AES";
      String digestAlg = "SHA-256";
      int keyLength = 128;
      PACEMappingResult mappingResult = null;

      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", BC_PROVIDER);
      keyPairGenerator.initialize(256);
      KeyPair piccKeyPair = keyPairGenerator.generateKeyPair();
      PublicKey piccPublicKey = piccKeyPair.getPublic();

      KeyPair pcdKeyPair = keyPairGenerator.generateKeyPair();

      SecretKey encKey = getRandomAESKey();
      SecretKey macKey = getRandomAESKey();

      SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(encKey, macKey, PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, true, 0L);
      SecureMessagingWrapper anotherWrapper = new AESSecureMessagingWrapper(encKey, macKey, 0L);

      byte[] chipAuthenticationData = new byte[8]; // FIXME: Generate randomly.

      byte[] encryptedChipAuthenticationData = new byte[128]; // FIXME: Encrypt chipAuthenticationData ourselves.

      PACECAMResult paceCAMResult = new PACECAMResult(paceKey, agreementAlg, cipherAlg, digestAlg, keyLength, mappingResult, pcdKeyPair, piccPublicKey, encryptedChipAuthenticationData, chipAuthenticationData, wrapper);
      PACECAMResult anotherPACECAMResult = new PACECAMResult(paceKey, agreementAlg, cipherAlg, digestAlg, keyLength, mappingResult, pcdKeyPair, piccPublicKey, encryptedChipAuthenticationData, chipAuthenticationData, anotherWrapper);

      assertEquals(paceCAMResult.hashCode(), anotherPACECAMResult.hashCode());
      assertEquals(paceCAMResult, anotherPACECAMResult);
      assertEquals(paceCAMResult.toString(), anotherPACECAMResult.toString());
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }

  private static SecretKey getRandomAESKey() throws NoSuchAlgorithmException {
    KeyGenerator keyFactory = KeyGenerator.getInstance("AES");
    return keyFactory.generateKey();
  }
}
