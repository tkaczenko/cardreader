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
 * $Id: PACEKeySpecTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test;

import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.BACKey;
import org.jmrtd.PACEKeySpec;
import org.jmrtd.PACESecretKeySpec;
import org.jmrtd.PassportService;

import junit.framework.TestCase;

public class PACEKeySpecTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public void testPACEKeySpec() {
    try {
      String can = "12345";
      PACEKeySpec paceCANKey = PACEKeySpec.createCANKey(can);
      assertEquals("PACE", paceCANKey.getAlgorithm());
      assertNotNull(paceCANKey.getKey());
      assertTrue(Arrays.equals(can.getBytes("UTF-8"), paceCANKey.getKey()));
      assertEquals(PassportService.CAN_PACE_KEY_REFERENCE, paceCANKey.getKeyReference());

      PACEKeySpec paceMRZKey = PACEKeySpec.createMRZKey(new BACKey("123456789", "710121", "331231"));
      assertEquals("PACE", paceMRZKey.getAlgorithm());
      assertNotNull(paceMRZKey.getKey());
      assertEquals(PassportService.MRZ_PACE_KEY_REFERENCE, paceMRZKey.getKeyReference());

      PACEKeySpec pacePINKey = PACEKeySpec.createPINKey("0000");
      assertEquals("PACE", pacePINKey.getAlgorithm());
      assertNotNull(pacePINKey.getKey());
      assertEquals(PassportService.PIN_PACE_KEY_REFERENCE, pacePINKey.getKeyReference());

      PACEKeySpec pacePUKKey = PACEKeySpec.createPUKKey("12345678");
      assertEquals("PACE", pacePUKKey.getAlgorithm());
      assertNotNull(pacePUKKey.getKey());
      assertEquals(PassportService.PUK_PACE_KEY_REFERENCE, pacePUKKey.getKeyReference());

    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }

  public void testPACESecretKeySpec() {
    try {
      String algorithm = "AES"; // ???
      byte keyRef = PassportService.CAN_PACE_KEY_REFERENCE;
      PACESecretKeySpec paceSecretKeySpec = new PACESecretKeySpec("12345".getBytes("UTF-8"), algorithm, keyRef);
      assertEquals(algorithm, paceSecretKeySpec.getAlgorithm());
      assertEquals(keyRef, paceSecretKeySpec.getKeyReference());
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }
}
