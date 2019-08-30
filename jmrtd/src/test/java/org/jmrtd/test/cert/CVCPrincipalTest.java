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
 * $Id: CVCPrincipalTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.cert;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.cert.CVCPrincipal;
import org.jmrtd.lds.icao.ICAOCountry;

import junit.framework.TestCase;
import net.sf.scuba.data.TestCountry;

public class CVCPrincipalTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public void testCVCPrincipalFromUT() {
    CVCPrincipal principal = new CVCPrincipal("UTDVCS00001");
    assertEquals(TestCountry.UT, principal.getCountry());
  }

  public void testCVCPrincipalFromNL() {
    CVCPrincipal principal = new CVCPrincipal("NLDVCS00001");
    assertEquals(ICAOCountry.getInstance("NLD"), principal.getCountry());
  }

  public void testCVCPrincipalFromUnknown() {
    try {
      CVCPrincipal principal = new CVCPrincipal("XYDVCS00001");
      assertNotNull(principal.getCountry());
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }

}
