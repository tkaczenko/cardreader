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
 * $Id: CountryTest.java 1751 2018-01-15 15:35:45Z martijno $
 */

package org.jmrtd.test.lds;

import org.jmrtd.lds.icao.ICAOCountry;

import junit.framework.TestCase;
import net.sf.scuba.data.Country;
import net.sf.scuba.data.ISOCountry;
import net.sf.scuba.data.UnicodeCountry;

public class CountryTest extends TestCase {

  public void testCountryValues() {
    Country[] values = Country.values();
    assertNotNull(values);
    for (Country country: values) {
      // LOGGER.info("DEBUG: country = " + country);
    }
  }

  public void testGermany() {
    Country icaoGermany = ICAOCountry.getInstance("D<<");
    Country isoGermany = Country.getInstance("DEU");
    assertNotNull(icaoGermany);
    assertTrue(ISOCountry.DE == isoGermany || UnicodeCountry.DE == isoGermany);
    assertTrue(ISOCountry.DE.equals(isoGermany) || UnicodeCountry.DE.equals(isoGermany));
    assertEquals(ICAOCountry.DE, icaoGermany);
    assertSame(ICAOCountry.DE, icaoGermany);
    assertEquals(isoGermany.toAlpha2Code(), icaoGermany.toAlpha2Code());
  }

  public void testTaiwan() {
    Country icaoCountry = ICAOCountry.getInstance("TWN");
    assertNotNull(icaoCountry);
    Country unicodeCountry = Country.getInstance("TWN");
    assertNotNull(unicodeCountry);
    assertEquals(icaoCountry, unicodeCountry);
    assertFalse(icaoCountry.getName().toLowerCase().contains("china"));
  }

  public void testNetherlands() {
    assertTrue(Country.getInstance("NLD") == ISOCountry.NL || Country.getInstance("NLD") == UnicodeCountry.NL);
    assertTrue(ISOCountry.NL.equals(Country.getInstance("NLD")) || UnicodeCountry.NL.equals(Country.getInstance("NLD")));
    assertEquals(ISOCountry.NL.getName(), UnicodeCountry.NL.getName());
  }

  public void testUtopia() {
    Country utopia = Country.getInstance("UT");
    assertNotNull(utopia);
    Country alsoUtopia = Country.getInstance("UTO");
    assertNotNull(alsoUtopia);
    assertEquals(alsoUtopia, utopia);
  }
}
