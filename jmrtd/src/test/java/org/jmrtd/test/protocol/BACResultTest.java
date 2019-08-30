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
 * $Id: BACResultTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.protocol;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.jmrtd.AccessKeySpec;
import org.jmrtd.BACKey;
import org.jmrtd.PassportService;
import org.jmrtd.protocol.BACResult;
import org.jmrtd.protocol.DESedeSecureMessagingWrapper;
import org.jmrtd.protocol.SecureMessagingWrapper;

import junit.framework.TestCase;

/**
 * Test cases for BACResult, the result of the BAC protocol.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1813 $
 *
 * @since 0.6.2
 */
public class BACResultTest extends TestCase {

  public void testBACResult() {
    try {
      BACResult bacResult = new BACResult(new BACKey("123456789", "700101", "171108"), new DESedeSecureMessagingWrapper(getRandomDESedeKey(), getRandomDESedeKey(), PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, true, 0L));
      AccessKeySpec bacKey = bacResult.getBACKey();
      assertNotNull(bacKey);
      assertEquals(new BACKey("123456789", "700101", "171108"), bacKey);

      SecureMessagingWrapper wrapper = bacResult.getWrapper();
      assertNotNull(wrapper);

    } catch (Exception e) {
      fail(e.getMessage());
    }
  }

  public void testBACResultEquals() {
    try {
      SecretKey encKey = getRandomDESedeKey();
      SecretKey macKey = getRandomDESedeKey();
      BACResult bacResult = new BACResult(new BACKey("123456789", "700101", "171108"), new DESedeSecureMessagingWrapper(encKey, macKey, PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, true, 0L));
      BACResult anotherBACResult = new BACResult(new BACKey("123456789", "700101", "171108"), new DESedeSecureMessagingWrapper(encKey, macKey, PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, true, 0L));
      assertEquals(bacResult.hashCode(), anotherBACResult.hashCode());
      assertEquals(bacResult, anotherBACResult);
      assertEquals(bacResult.toString(), anotherBACResult.toString());
    } catch (Exception e) {
      fail(e.getMessage());
    }
  }

  private static SecretKey getRandomDESedeKey() throws NoSuchAlgorithmException {
    KeyGenerator keyFactory = KeyGenerator.getInstance("DESede");
    return keyFactory.generateKey();
  }
}
