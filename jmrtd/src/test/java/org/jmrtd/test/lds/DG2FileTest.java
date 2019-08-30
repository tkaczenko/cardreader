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
 * $Id: DG2FileTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.lds;

//import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.jmrtd.lds.iso19794.FaceInfo;
import org.jmrtd.test.ResourceUtil;

import junit.framework.TestCase;
import net.sf.scuba.util.Hex;

public class DG2FileTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private static final String BSI_TEST_FILE = "/lds/bsi2008/Datagroup2.bin";
  private static final String LOES_TEST_FILE = "/lds/loes2006/ef0102.bin";

  private static final boolean SHOULD_SHOW_FRAME = false;

  public DG2FileTest(String name) {
    super(name);
  }

  public void testConstruct() {
    try {
      DG2File dg2 = new DG2File(Arrays.asList(new FaceInfo[] { }));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  private static byte[] readBytes(InputStream is) throws IOException {
    return readBytes(is, 16384);
    //		return readBytes(is, 168);
  }

  private static byte[] readBytes(InputStream is, int blockSize) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    int nRead;
    byte[] data = new byte[blockSize];
    while ((nRead = is.read(data, 0, data.length)) != -1) {
      buffer.write(data, 0, nRead);
    }
    buffer.flush();
    return buffer.toByteArray();
  }

  public void testReflexive() {
    try {
      testReflexive(getTestObject(BSI_TEST_FILE));
      testReflexive(getTestObject(LOES_TEST_FILE));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testReflexive(DG2File dg2File) {
    try {
      byte[] encoded = dg2File.getEncoded();
      assertNotNull(encoded);
      ByteArrayInputStream in = new ByteArrayInputStream(encoded);
      DG2File copy = new DG2File(in);

      assertEquals(dg2File, copy);
      assertEquals(Hex.bytesToHexString(encoded), Hex.bytesToHexString(copy.getEncoded()));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testWriteObject() {
    try {
      testDecodeEncode(getTestObject(BSI_TEST_FILE), 2);
      testDecodeEncode(getTestObject(LOES_TEST_FILE), 2);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  /**
   * Tests if we can decode and then encode.
   *
   * @param dg2File
   * @param n number of times
   */
  public void testDecodeEncode(DG2File dg2File, int n) {
    try {
      byte[] encoded = null;

      List<FaceInfo> records = dg2File.getFaceInfos();
      int faceCount = records.size();
      FaceInfo record = faceCount == 0 ? null : records.get(0);
      List<FaceImageInfo> images = record.getFaceImageInfos();
      int faceImageCount = images.size();
      FaceImageInfo faceImage = faceImageCount == 0 ? null : images.get(0);
      int width = faceImageCount == 0 ? -1 : faceImage.getWidth(), height = faceImageCount == 0 ? -1 : faceImage.getHeight();

      for (int i = 0; i < n; i++) {
        encoded = dg2File.getEncoded();
        dg2File = new DG2File(new ByteArrayInputStream(encoded));
      }

      List<FaceInfo> records1 = dg2File.getFaceInfos();
      int faceCount1 = records1.size();
      FaceInfo record1 = faceCount1 == 0 ? null : records1.get(0);
      List<FaceImageInfo> images1 = record1.getFaceImageInfos();
      int faceImageCount1 = images1.size();
      FaceImageInfo faceImage1 = faceImageCount1 == 0 ? null : images1.get(0);
      int width1 = faceImageCount1 == 0 ? -1 : faceImage1.getWidth(), height1 = faceImageCount1 == 0 ? -1 : faceImage1.getHeight();

      assertEquals(width, width1);
      assertEquals(height, height1);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testElements() {
    try {
      testElements(getTestObject(BSI_TEST_FILE));
      testElements(getTestObject(LOES_TEST_FILE));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testElements(DG2File dg2File) {
    testDecodeEncode(dg2File, 2);

    FaceInfoTest faceInfoTest = new FaceInfoTest("DG2FileTest");
    List<FaceInfo> faceInfos = dg2File.getFaceInfos();
//    LOGGER.info("DEBUG: faceInfos: " + faceInfos.size());
    for (FaceInfo faceInfo: faceInfos) {
      faceInfoTest.testMandatorySBHFields(faceInfo);
      faceInfoTest.testOptionalSBHFields(faceInfo);
      faceInfoTest.testElements(faceInfo);
    }
  }

  public void testImageBytes() {
    try {
      testImageBytes(getTestObject(BSI_TEST_FILE));
      testImageBytes(getTestObject(LOES_TEST_FILE));
    } catch (IOException ioe) {
      LOGGER.log(Level.WARNING, "Exception", ioe);
      fail(ioe.getMessage());
    }
  }

  public void testImageBytes(DG2File dg2) {
    try {
      FaceImageInfo i1 = dg2.getFaceInfos().get(0).getFaceImageInfos().get(0);
      int l1 = i1.getImageLength();
      byte[] b1 = new byte[l1];
      (new DataInputStream(i1.getImageInputStream())).readFully(b1);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testImageBytes0() {
    testImageBytes0(BSI_TEST_FILE);
    testImageBytes0(LOES_TEST_FILE);
  }

  public void testImageBytes0(String testFile) {
    try {
      InputStream inputStream = ResourceUtil.getInputStream(testFile);

      DG2File dg2 = new DG2File(inputStream);
      FaceImageInfo i1 = dg2.getFaceInfos().get(0).getFaceImageInfos().get(0);
      int l1 = i1.getImageLength();
      byte[] b1 = new byte[l1];
      (new DataInputStream(i1.getImageInputStream())).readFully(b1);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testCreate() {
    try {
      DG2File dg2 = createTestObject();
      byte[] header = new byte[256];
      System.arraycopy(dg2.getEncoded(), 0, header, 0, header.length);
      //			LOGGER.info(Hex.bytesToPrettyString(header));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testTruncate() {
    try {
      DG2File dg2File = getDefaultTestObject();
      byte[] dg2Bytes = dg2File.getEncoded();
      byte[] partialBytes = new byte[(int)(0.8 * dg2Bytes.length)];
      System.arraycopy(dg2Bytes, 0, partialBytes, 0, partialBytes.length);
      DG2File partialDG2File = new DG2File(new ByteArrayInputStream(partialBytes));
      fail("Should be exception");
    } catch (Exception expected) {
      LOGGER.log(Level.INFO, "Exception", expected);
    }
  }

  public static DG2File createTestObject() {
    try {
      FaceInfo faceInfo = FaceInfoTest.createTestObject();
      DG2File dg2 = new DG2File(Arrays.asList(new FaceInfo[] { faceInfo }));
      return dg2;
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
      return null;
    }
  }

  public static DG2File getDefaultTestObject() throws IOException {
    return getTestObject(BSI_TEST_FILE);
  }

  public static DG2File getTestObject(String fileName) throws IOException {
    return new DG2File(ResourceUtil.getInputStream(fileName));
  }

  public void testFile(InputStream in) {
    try {
      testDecodeEncode(new DG2File(in), 3);
    } catch (IOException e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }
}
