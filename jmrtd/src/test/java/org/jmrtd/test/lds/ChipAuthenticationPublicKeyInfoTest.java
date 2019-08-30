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
 * $Id: ChipAuthenticationPublicKeyInfoTest.java 1755 2018-01-20 09:50:07Z martijno $
 */

package org.jmrtd.test.lds;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo;

import junit.framework.TestCase;

public class ChipAuthenticationPublicKeyInfoTest extends TestCase {

  private static final Provider BC_PROVIDER = new BouncyCastleProvider();

  public void testConstruct() {
    try {
      ChipAuthenticationPublicKeyInfo chipAuthenticationPublicKeyInfo = getSampleObject();
    } catch (Exception e) {
      fail(e.getMessage());
    }
  }

  public void testChipAuthenticationPublicKeyInfoEquals() {
    ChipAuthenticationPublicKeyInfo chipAuthenticationPublicKeyInfo = getSampleObject();
    ChipAuthenticationPublicKeyInfo anotherChipAuthenticationPublicKeyInfo = new ChipAuthenticationPublicKeyInfo(chipAuthenticationPublicKeyInfo.getSubjectPublicKey(), chipAuthenticationPublicKeyInfo.getKeyId());
    assertEquals(chipAuthenticationPublicKeyInfo.hashCode(), anotherChipAuthenticationPublicKeyInfo.hashCode());
    assertEquals(chipAuthenticationPublicKeyInfo, anotherChipAuthenticationPublicKeyInfo);
    assertEquals(chipAuthenticationPublicKeyInfo.toString(), anotherChipAuthenticationPublicKeyInfo.toString());
  }

  public void testSerializable() {
    try {
      ChipAuthenticationPublicKeyInfo chipAuthenticationPublicKeyInfo = getSampleObject();
      ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
      ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
      objectOutputStream.writeObject(chipAuthenticationPublicKeyInfo);
    } catch (Exception e) {
      fail(e.getMessage());
    }

  }

  /** Elaborate sample. */
  public ChipAuthenticationPublicKeyInfo getSampleObject() {
    try {
      /* Using BC here, since SunJCE doesn't support EC. */
      KeyPairGenerator keyGen1 = KeyPairGenerator.getInstance("EC", BC_PROVIDER);
      keyGen1.initialize(192);
      KeyPair keyPair1 = keyGen1.generateKeyPair();

      PublicKey publicKey1 = keyPair1.getPublic();

      return new ChipAuthenticationPublicKeyInfo(publicKey1, BigInteger.valueOf(1));
    } catch(Exception e) {
      fail(e.getMessage());
      return null;
    }
  }
}
