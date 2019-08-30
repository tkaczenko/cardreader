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
 * $Id: COMFileTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.lds;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.lds.LDSFile;
import org.jmrtd.lds.icao.COMFile;

import junit.framework.TestCase;

public class COMFileTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public COMFileTest(String name) {
    super(name);
  }

  public void testToString() {
    COMFile dg1File = createTestObject();
    String expectedResult = "COMFile LDS 01.07, Unicode 04.00.00, [DG1, DG2, DG15]";
    assertEquals(dg1File.toString(), expectedResult);
  }

  public void testReflexive() {
    testReflexive(createTestObject());
  }

  private void testReflexive(COMFile comFile) {
    try {
      byte[] encoded = comFile.getEncoded();
      assertNotNull(encoded);
      ByteArrayInputStream in = new ByteArrayInputStream(encoded);
      COMFile copy = new COMFile(in);
      assertEquals(comFile, copy);
      byte[] encodedCopy = copy.getEncoded();
      assertNotNull(encodedCopy);
      assertEquals(encoded.length, encodedCopy.length);
      assertTrue(java.util.Arrays.equals(encoded, encodedCopy));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testSpecSample() {
    byte[] bytes = { 0x60, /* L */ 0x16,
        0x5F, 0x01, /* L */ 0x04,
        '0', '1', '0', '7',
        0x5F, 0x36, /* L */ 0x06,
        '0', '4', '0', '0', '0', '0',
        0x5C, /* L */ 0x04,
        0x61, 0x75, 0x76, 0x6C };

    ByteArrayInputStream in = new ByteArrayInputStream(bytes);
    try {
      COMFile comFile = new COMFile(in);
      assertEquals(comFile.getLDSVersion(), "1.7");
      assertEquals(comFile.getUnicodeVersion(), "4.0.0");

      int[] tagList = comFile.getTagList();
      assertNotNull(tagList);
      assertEquals(tagList.length, 4);
      assertEquals(tagList[0], COMFile.EF_DG1_TAG);
      assertEquals(tagList[1], COMFile.EF_DG2_TAG);
      assertEquals(tagList[2], COMFile.EF_DG4_TAG);
      assertEquals(tagList[3], COMFile.EF_DG12_TAG);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testAlternativeConstructor() {
    int[] tagList1 = new int[2];
    tagList1[0] = LDSFile.EF_DG1_TAG;
    tagList1[1] = LDSFile.EF_DG2_TAG;
    int[] tagList2 = new int[tagList1.length];
    System.arraycopy(tagList1, 0, tagList2, 0, tagList1.length);
    assertNotNull(tagList1);
    assertNotNull(tagList2);
    assertTrue(java.util.Arrays.equals(tagList1, tagList2));
    COMFile comFile1 = new COMFile("01", "07", "04", "00", "00", tagList1);
    COMFile comFile2 = new COMFile("1.7", "4.0.0", tagList2);
    assertEquals(comFile1, comFile2);
    assertEquals(comFile2.getLDSVersion(), "1.7");
    assertEquals(comFile2.getUnicodeVersion(), "4.0.0");

    assertEquals(new COMFile("01.7", "4.00.0", tagList1), new COMFile("1.07", "04.0.00", tagList2));
  }

  public static COMFile createTestObject() {
    int[] tagList = new int[3];
    tagList[0] = LDSFile.EF_DG1_TAG;
    tagList[1] = LDSFile.EF_DG2_TAG;
    tagList[2] = LDSFile.EF_DG15_TAG;
    return new COMFile("01", "07", "04", "00", "00", tagList);
  }

  public void testFile(InputStream in) {
    try {
      testReflexive(new COMFile(in));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }
}
