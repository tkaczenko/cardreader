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
 * $Id: DG1FileTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.lds;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;

import junit.framework.TestCase;
import net.sf.scuba.util.Hex;

public class DG1FileTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public DG1FileTest(String name) {
    super(name);
  }

  public void testToString() {
    DG1File dg1File = createTestObject();
    String expectedResult = "DG1File P<NLDMEULENDIJK<<LOES<ALBERTINE<<<<<<<<<<<<<XX00000000NLD7110195F1108280123456782<<<<<<2";
    assertEquals(dg1File.toString(), expectedResult);
  }

  public void testReflexive() {
    testReflexive(createTestObject());
  }

  public void testReflexive(DG1File dg1File) {
    try {
      byte[] encoded = dg1File.getEncoded();
      ByteArrayInputStream in = new ByteArrayInputStream(encoded);
      DG1File copy = new DG1File(in);
      assertEquals(dg1File, copy);
      assertEquals(Hex.bytesToHexString(encoded), Hex.bytesToHexString(copy.getEncoded()));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  private static final String SMITH_SAMPLE = "P<ATASMITH<<JOHN<T<<<<<<<<<<<<<<<<<<<<<<<<<<123456789<HMD7406222M10123130121<<<<<<<<<<54";
  private static final String LOES_SAMPLE = "P<NLDMEULENDIJK<<LOES<ALBERTINE<<<<<<<<<<<<<XA00277324NLD7110195F0610010123456782<<<<<08";

  public void testSpecSample() {
    try {
      DG1File file = getSpecSampleObject(SMITH_SAMPLE);
      assertEquals(file.getMRZInfo().toString().replace("\n", "").trim(), SMITH_SAMPLE);

      file = getSpecSampleObject(LOES_SAMPLE);
      assertEquals(file.getMRZInfo().toString().replace("\n", "").trim(), LOES_SAMPLE);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testLength() {
    Collection<DG1File> dg1s = getTestObjects();
    for (DG1File dg1: dg1s) {
      testLength(dg1);
    }
  }

  public void testLength(DG1File dg1) {
    byte[] encoded = dg1.getEncoded();
    assertNotNull(encoded);

    int length = dg1.getLength();
    if (length <= 0) {
      LOGGER.info("DEBUG: O_o: length = " + length);
    }
    assertTrue(length > 0);

    assertTrue(length <= encoded.length);
  }

  public Collection<DG1File> getTestObjects() {
    List<DG1File> testObjects = new ArrayList<DG1File>();
    try {
      testObjects.add(createTestObject());
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
    }
    try {
      testObjects.add(getSpecSampleObject(SMITH_SAMPLE));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
    }
    try {
      testObjects.add(getSpecSampleObject(LOES_SAMPLE));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
    }
    return testObjects;
  }

  public DG1File getSpecSampleObject(String str) {
    byte[] header = { 0x61, 0x5B, 0x5F, 0x1F, 0x58 };
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      out.write(header);
      out.write(str.getBytes("UTF-8"));
      out.flush();
      byte[] bytes = out.toByteArray();
      ByteArrayInputStream in = new ByteArrayInputStream(bytes);
      return new DG1File(in);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
    }

    return null;
  }

  public static DG1File createTestObject() {
    MRZInfo mrzInfo = MRZInfoTest.createTestObject();
    return new DG1File(mrzInfo);
  }

  public void testFile(InputStream in) {
    try {
      testReflexive(new DG1File(in));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }
}
