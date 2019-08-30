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
 * $Id: UnlimitedStrengthCryptoTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;

import junit.framework.TestCase;

/**
 * Tests explicitly if we have unlimited strength cryptography installed on this VM.
 *
 * @author The JMRTD team
 *
 * @version $Revision: 1813 $
 */
public class UnlimitedStrengthCryptoTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public void testUnlimitedStrength() {
    try {
//      LOGGER.info("DEBUG: Checking unlimited crypto for VM " +  System.getProperties());
      assertTrue(Cipher.getMaxAllowedKeyLength("AES") >= 256);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }
}
