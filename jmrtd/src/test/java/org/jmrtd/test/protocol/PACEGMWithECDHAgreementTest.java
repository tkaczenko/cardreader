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
 * $Id: PACEGMWithECDHAgreementTest.java 1751 2018-01-15 15:35:45Z martijno $
 */

package org.jmrtd.test.protocol;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.ECPoint;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.Util;
import org.jmrtd.protocol.PACEGMWithECDHAgreement;

import junit.framework.TestCase;

public class PACEGMWithECDHAgreementTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private static final Provider BC_PROVIDER = Util.getBouncyCastleProvider();

  public void testPACEGMWithECDHAgreementSameSharedPoint() {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BC_PROVIDER);
      keyPairGenerator.initialize(256);

      KeyPair piccKeyPair = keyPairGenerator.generateKeyPair();
      PublicKey piccPublicKey = piccKeyPair.getPublic();
      PrivateKey piccPrivateKey = piccKeyPair.getPrivate();

      KeyPair pcdKeyPair = keyPairGenerator.generateKeyPair();
      PublicKey pcdPublicKey = pcdKeyPair.getPublic();
      PrivateKey pcdPrivateKey = pcdKeyPair.getPrivate();

      PACEGMWithECDHAgreement agreement = new PACEGMWithECDHAgreement();
      agreement.init(pcdPrivateKey);
      ECPoint sharedPoint = agreement.doPhase(piccPublicKey);

      PACEGMWithECDHAgreement otherAgreement = new PACEGMWithECDHAgreement();
      otherAgreement.init(piccPrivateKey);
      otherAgreement.doPhase(pcdPublicKey);
      ECPoint otherSharedPoint = otherAgreement.doPhase(pcdPublicKey);

      assertEquals(sharedPoint, otherSharedPoint);
      assertEquals(otherSharedPoint, sharedPoint);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
    }
  }
}
