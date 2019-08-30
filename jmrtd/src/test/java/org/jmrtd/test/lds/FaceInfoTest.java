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
 * $Id: FaceInfoTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.lds;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.cbeff.ISO781611;
import org.jmrtd.cbeff.StandardBiometricHeader;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.jmrtd.lds.iso19794.FaceInfo;

import junit.framework.TestCase;

public class FaceInfoTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public FaceInfoTest(String name) {
    super(name);
  }

  public void testToString() {
    try {
      FaceInfo info = createTestObject();
      assertNotNull(info);
      String asString = info.toString();
      assertNotNull(asString);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testElements() {
    FaceInfo faceInfo = createTestObject();
    testElements(faceInfo);
  }

  public void testElements(FaceInfo FaceInfo) {
    List<FaceImageInfo> imageInfos = FaceInfo.getFaceImageInfos();
    for (FaceImageInfo imageInfo: imageInfos) {
      FaceImageInfoTest imageInfoTest = new FaceImageInfoTest("FaceInfoTest_testElements");
      imageInfoTest.testEncodeDecode(imageInfo);
    }
  }

  public void testSBHFields() {
    try {
      FaceInfo faceInfo = createTestObject();
      testMandatorySBHFields(faceInfo);
      testOptionalSBHFields(faceInfo);

      byte[] faceInfoEncoded = faceInfo.getEncoded();

      StandardBiometricHeader sbh = faceInfo.getStandardBiometricHeader();
      Map<Integer, byte[]> sbhElements = new HashMap<Integer, byte[]>();
      sbhElements.put(0x87, sbh.getElements().get(0x87)); // FORMAT_OWNER
      sbhElements.put(0x88, sbh.getElements().get(0x88)); // FORMAT_TYPE

      FaceInfo faceInfoMinimalSBH = new FaceInfo(new StandardBiometricHeader(sbhElements), new ByteArrayInputStream(faceInfoEncoded));

      testMandatorySBHFields(faceInfoMinimalSBH);
    } catch (Exception e) {
      fail(e.getMessage());
    }
  }

  /*
   * Doc 9303 says:
   * - Biometric type (Optional, but mandatory if subtype specified) // FIXME: is this true?
   * - Biometric subtype (Optional for DG2, mandatory for DG3, DG4.)
   * - Creation date and time (Optional)
   * - Validity period (from through) (Optional)
   * - Creator of the biometric reference data(PID) (Optional)
   * - Format owner (Mandatory)
   * - Format type (Mandatory)
   *
   * In practice this means: 0x81 (bio type), 0x82 (bio subtype),
   * 0x87 (format owner), 0x88 (format type) will be present.
   */
  public void testMandatorySBHFields(FaceInfo faceInfo) {
    StandardBiometricHeader sbh = faceInfo.getStandardBiometricHeader();
    Set<Integer> tags = sbh.getElements().keySet();
    assertTrue(tags.contains(0x87)); assertTrue(tags.contains(ISO781611.FORMAT_OWNER_TAG));
    assertTrue(tags.contains(0x88)); assertTrue(tags.contains(ISO781611.FORMAT_TYPE_TAG));
  }

  public void testOptionalSBHFields(FaceInfo faceInfo) {
    Integer[] possibleTagsArray = { 0x81, 0x82, 0x83, /* 0x84, */ 0x85, 0x86, 0x87, 0x88 };
    Set<Integer> possibleTags = new HashSet<Integer>(Arrays.asList(possibleTagsArray));
    StandardBiometricHeader sbh = faceInfo.getStandardBiometricHeader();
    Set<Integer> tags = sbh.getElements().keySet();
    for (int tag: tags) {
      assertTrue(possibleTags.contains(tag));
    }
  }

  public void testTruncate() {
    try {
      FaceInfo faceInfo = createTestObject();
      byte[] bytes = faceInfo.getEncoded();
      byte[] partialBytes = new byte[(int)(0.8 * bytes.length)];
      System.arraycopy(bytes, 0, partialBytes, 0, partialBytes.length);
      FaceInfo partialFaceInfo = new FaceInfo(new ByteArrayInputStream(partialBytes));
      fail("Should be exception");
    } catch (Exception expected) {
      LOGGER.log(Level.INFO, "Expected", expected);
    }
  }

  public void testEncoded() {
    try {
      FaceInfo faceInfo = createTestObject();
      byte[] encoded = faceInfo.getEncoded();
      FaceInfo faceInfo2 = new FaceInfo(faceInfo.getStandardBiometricHeader(), new ByteArrayInputStream(encoded));
      LOGGER.info("DEBUG: faceInfo = " + faceInfo);
      assertEquals(faceInfo, faceInfo2);
      assertEquals(faceInfo.toString(), faceInfo2.toString());
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public static FaceInfo createTestObject() {
    List<FaceImageInfo> FaceImageInfos = new LinkedList<FaceImageInfo>();
    FaceImageInfo FaceImageInfo = FaceImageInfoTest.createTestObject();
    FaceImageInfos.add(FaceImageInfo);
    FaceInfo FaceInfo = new FaceInfo(FaceImageInfos);
    return FaceInfo;
  }
}
