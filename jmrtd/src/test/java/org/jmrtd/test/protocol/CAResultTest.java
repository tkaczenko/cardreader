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
 * $Id: CAResultTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.protocol;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.jmrtd.PassportService;
import org.jmrtd.Util;
import org.jmrtd.protocol.AESSecureMessagingWrapper;
import org.jmrtd.protocol.EACCAProtocol;
import org.jmrtd.protocol.EACCAResult;
import org.jmrtd.protocol.SecureMessagingWrapper;

import junit.framework.TestCase;

/**
 * Tests for CAResult class.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1813 $
 *
 * @since 0.6.2
 */
public class CAResultTest extends TestCase {

  private static final Provider BC_PROVIDER = Util.getBouncyCastleProvider();

  public void testCAResult() {
    try {
      BigInteger keyId = BigInteger.valueOf(-1L);

      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", BC_PROVIDER);
      keyPairGenerator.initialize(256);
      KeyPair piccKeyPair = keyPairGenerator.generateKeyPair();
      PublicKey piccPublicKey = piccKeyPair.getPublic();

      KeyPair pcdKeyPair = keyPairGenerator.generateKeyPair();
      PublicKey pcdPublicKey = pcdKeyPair.getPublic();
      PrivateKey pcdPrivateKey = pcdKeyPair.getPrivate();

      SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(getRandomAESKey(), getRandomAESKey(), PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, true, 0L);

      EACCAResult caResult = new EACCAResult(keyId, piccPublicKey, EACCAProtocol.getKeyHash("ECDH", pcdPublicKey), pcdPublicKey, pcdPrivateKey, wrapper);

      assertEquals(piccPublicKey, caResult.getPublicKey());

      assertEquals(pcdPublicKey, caResult.getPCDPublicKey());
      assertEquals(pcdPrivateKey, caResult.getPCDPrivateKey());

      assertEquals(wrapper, caResult.getWrapper());
    } catch (Exception e) {
      fail(e.getMessage());
    }
  }

  public void testCAResultEquals() {
    try {
      BigInteger keyId = BigInteger.valueOf(-1L);

      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", BC_PROVIDER);
      keyPairGenerator.initialize(256);
      KeyPair piccKeyPair = keyPairGenerator.generateKeyPair();
      PublicKey piccPublicKey = piccKeyPair.getPublic();

      KeyPair pcdKeyPair = keyPairGenerator.generateKeyPair();
      PublicKey pcdPublicKey = pcdKeyPair.getPublic();
      PrivateKey pcdPrivateKey = pcdKeyPair.getPrivate();

      SecretKey encKey = getRandomAESKey();
      SecretKey macKey = getRandomAESKey();
      SecureMessagingWrapper wrapper = new AESSecureMessagingWrapper(encKey, macKey, PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, true, 0L);
      SecureMessagingWrapper anotherWrapper = new AESSecureMessagingWrapper(encKey, macKey, 256, true, 0L);

      EACCAResult caResult = new EACCAResult(keyId, piccPublicKey, EACCAProtocol.getKeyHash("ECDH", pcdPublicKey), pcdPublicKey, pcdPrivateKey, wrapper);
      EACCAResult anotherCAResult = new EACCAResult(keyId, piccPublicKey, EACCAProtocol.getKeyHash("ECDH", pcdPublicKey), pcdPublicKey, pcdPrivateKey, anotherWrapper);

      assertEquals(caResult.hashCode(), anotherCAResult.hashCode());
      assertEquals(caResult, anotherCAResult);
      assertEquals(caResult.toString(), anotherCAResult.toString());
    } catch (Exception e) {
      fail(e.getMessage());
    }
  }

  private static SecretKey getRandomAESKey() throws NoSuchAlgorithmException {
    KeyGenerator keyFactory = KeyGenerator.getInstance("AES");
    return keyFactory.generateKey();
  }

}
