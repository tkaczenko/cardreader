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
 * $Id: CardSecurityFileTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.lds;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.lds.CardSecurityFile;
import org.jmrtd.lds.SecurityInfo;
import org.jmrtd.test.ResourceUtil;

import junit.framework.TestCase;

/**
 * Tests for the CardSecurity file.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1813 $
 *
 * @since 0.5.6
 */
public class CardSecurityFileTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public void testParseSampleCardSecurityFileFromResource() {
    try {
      InputStream inputStream = createSampleInputStream();
      CardSecurityFile cardSecurityFile = new CardSecurityFile(inputStream);
      testAttributesSHA256withECDSASample(cardSecurityFile);

      /* Re-encode it, and test again. */
      byte[] encoded = cardSecurityFile.getEncoded();
      assertNotNull(encoded);
      CardSecurityFile cardSecurityFile2 = new CardSecurityFile(new ByteArrayInputStream(encoded));

      testSimilar(cardSecurityFile, cardSecurityFile2);

      testAttributesSHA256withECDSASample(cardSecurityFile2);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }

  private void testSimilar(CardSecurityFile cardSecurityFile, CardSecurityFile cardSecurityFile2) {
    assertEquals(cardSecurityFile.hashCode(), cardSecurityFile2.hashCode());
    assertEquals(cardSecurityFile, cardSecurityFile2);
    assertEquals(cardSecurityFile.getDigestAlgorithm(), cardSecurityFile2.getDigestAlgorithm());
    assertEquals(cardSecurityFile.getDigestEncryptionAlgorithm(), cardSecurityFile2.getDigestEncryptionAlgorithm());
    assertEquals(cardSecurityFile.toString(), cardSecurityFile2.toString());
  }

  public void testAttributesSHA256withECDSASample(CardSecurityFile cardSecurityFile) {
    assertEquals("SHA-256", cardSecurityFile.getDigestAlgorithm());
    assertEquals("SHA256withECDSA", cardSecurityFile.getDigestEncryptionAlgorithm());

    Collection<SecurityInfo> securityInfos = cardSecurityFile.getSecurityInfos();

    assertNotNull(securityInfos);

    assertTrue(securityInfos.size() > 0);

//    for (SecurityInfo securityInfo: securityInfos) {
//      LOGGER.info("DEBUG: securityInfo = " + securityInfo);
//    }
  }

  public InputStream createSampleInputStream() {
    try {
      return ResourceUtil.getInputStream("/efcardsecurity/efcardsecurity.dump");
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
      return null;
    }
  }
}
