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
 * $Id: ActiveAuthenticationInfoTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.lds;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.lds.ActiveAuthenticationInfo;

import junit.framework.TestCase;

public class ActiveAuthenticationInfoTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public void testActiveAuthenticationInfo() {
    ActiveAuthenticationInfo aaInfo = new ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID); //  0.4.0.127.0.7.1.1.4.1.3

    assertEquals(ActiveAuthenticationInfo.ID_AA, aaInfo.getObjectIdentifier());
    assertEquals("id-AA", aaInfo.getProtocolOIDString());
    assertEquals(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID, aaInfo.getSignatureAlgorithmOID());
  }

  public void testActiveAuthenticationInfoEquals() {
    ActiveAuthenticationInfo aaInfo = new ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID); //  0.4.0.127.0.7.1.1.4.1.3
    ActiveAuthenticationInfo anotherAAInfo = new ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID); //  0.4.0.127.0.7.1.1.4.1.3

    assertEquals(aaInfo.hashCode(), anotherAAInfo.hashCode());
    assertEquals(aaInfo, anotherAAInfo);
    assertEquals(aaInfo.toString(), anotherAAInfo.toString());
  }

  public void testActiveAuthenticationInfoSerializable() {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    try {
      ActiveAuthenticationInfo aaInfo = new ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID); //  0.4.0.127.0.7.1.1.4.1.3
      ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
      objectOutputStream.writeObject(aaInfo);
      objectOutputStream.flush();
      objectOutputStream.close();
      byte[] encoded = byteArrayOutputStream.toByteArray();
      ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(encoded));
      Object decodedObject = objectInputStream.readObject();
      assertNotNull(decodedObject);
      assertTrue(decodedObject instanceof ActiveAuthenticationInfo);
      assertEquals(aaInfo, decodedObject);
    } catch (Exception e) {
      fail(e.getMessage());
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
    } finally {
      try {
        byteArrayOutputStream.close();
      } catch (IOException ioe) {

      }
    }
  }
}
