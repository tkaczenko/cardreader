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
 * $Id: CardVerifiableCertificateTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.cert;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.cert.CVCAuthorizationTemplate;
import org.jmrtd.cert.CVCAuthorizationTemplate.Permission;
import org.jmrtd.cert.CVCAuthorizationTemplate.Role;
import org.jmrtd.cert.CVCPrincipal;
import org.jmrtd.cert.CardVerifiableCertificate;

import junit.framework.TestCase;

/**
 * Tests for the card verifiable certificate class.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1813 $
 *
 * @since 0.6.2
 */
public class CardVerifiableCertificateTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public void testCardVerifiableCertificate() {
    try {
      CVCPrincipal authorityReference = new CVCPrincipal("UTDVCS00001");
      CVCPrincipal holderReference = new CVCPrincipal("UTIS00001");

      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(1024);

      KeyPair keyPair = generator.generateKeyPair();
      PublicKey publicKey = keyPair.getPublic();

      String algorithm = "SHA256WithRSA";
      SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-dd-MM");
      Date notBefore = simpleDateFormat.parse("2017-01-01");
      Date notAfter = simpleDateFormat.parse("2017-02-02");
      Role role = Role.IS;
      Permission permission = Permission.READ_ACCESS_DG3_AND_DG4;
      byte[] signatureData = new byte[128]; // NOTE: replace this with a real sig.

      CardVerifiableCertificate cvCert = new CardVerifiableCertificate(authorityReference, holderReference, publicKey, algorithm, notBefore, notAfter, role, permission, signatureData);

      assertEquals(holderReference, cvCert.getHolderReference());
      assertEquals(authorityReference, cvCert.getAuthorityReference());

      assertEquals(new CVCAuthorizationTemplate(role, permission), cvCert.getAuthorizationTemplate());

      assertTrue(algorithm.equalsIgnoreCase(cvCert.getSigAlgName()));

      // FIXME: Can be 1 day of? -- MO
//      assertTrue(isSameDay(notBefore, cvCert.getNotBefore()));
//
//      assertTrue(isSameDay(notAfter, cvCert.getNotAfter()));

      assertEquals(publicKey, cvCert.getPublicKey());

    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }

  /* Adapted from: https://stackoverflow.com/a/2517954/27190 */
  private static boolean isSameDay(Date date1, Date date2) {
    SimpleDateFormat fmt = new SimpleDateFormat("yyyyMMdd");
    LOGGER.info("DEBUG: 1 = " + fmt.format(date1));
    LOGGER.info("DEBUG: 2 = " + fmt.format(date2));
    return fmt.format(date1).equals(fmt.format(date2));
  }

}
