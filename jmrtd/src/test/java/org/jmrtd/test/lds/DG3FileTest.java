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
 * $Id: DG3FileTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.lds;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.security.AccessControlException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.lds.icao.DG3File;
import org.jmrtd.lds.iso19794.FingerImageInfo;
import org.jmrtd.lds.iso19794.FingerInfo;
import org.jmrtd.test.ResourceUtil;

import junit.framework.TestCase;
import net.sf.scuba.util.Hex;

public class DG3FileTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private static final String TEST_FILE = "/lds/bsi2008/Datagroup3.bin";

  public DG3FileTest(String name) {
    super(name);
  }

  public void testConstruct() {
    try {
      DG3File dg3 = new DG3File(Arrays.asList(new FingerInfo[] { }));
      assertNotNull(dg3.getFingerInfos());
      assertTrue(dg3.getFingerInfos().isEmpty());
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testFile() {
    try {
      DG3File dg3 = getTestObjectFromResource();
      List<FingerInfo> recordInfos = dg3.getFingerInfos();
      int recordCount = recordInfos.size();
      int recordNumber = 1;
//      LOGGER.info("DEBUG: Number of finger records = " + recordCount);
      for (FingerInfo record: recordInfos) {
        List<FingerImageInfo> imageInfos = record.getFingerImageInfos();
        int imageInfoCount = imageInfos.size();
//        LOGGER.info("DEBUG: Number of images in record " + recordNumber + " is " + imageInfoCount);
        int imageInfoNumber = 1;
        for (FingerImageInfo imageInfo: imageInfos) {
          int length = imageInfo.getImageLength();
          byte[] bytes = new byte[length];
          DataInputStream dataIn = new DataInputStream(imageInfo.getImageInputStream());
          dataIn.readFully(bytes);
        }
        recordNumber ++;
      }
    } catch (AccessControlException ace) {
      LOGGER.info("DEBUG: *************** could not get access to DG3 *********");
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testDecodeEncode() {
    try {
      testDecodeEncode(ResourceUtil.getInputStream(TEST_FILE));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testDecodeEncode(InputStream in) {
    try {
      DG3File dg3 = new DG3File(in);

      byte[] encoded = dg3.getEncoded();

      //			File outputDir = new File("tmp");
      //			if (!outputDir.exists()) {
      //				if (!outputDir.mkdirs()) {
      //					fail("Could not make output dir \"" + outputDir.getAbsolutePath() + "\"");
      //				}
      //			}
      //			if (!outputDir.isDirectory()) {
      //				fail("Could not make output dir \"" + outputDir.getAbsolutePath() + "\"");
      //			}
      //			FileOutputStream origOut = new FileOutputStream(new File(outputDir, "dg3orig.bin"));
      //			origOut.write(encoded);
      //			origOut.flush();
      //			origOut.close();

      assertNotNull(encoded);

      DG3File copy = new DG3File(new ByteArrayInputStream(encoded));

      byte[] encodedCopy = copy.getEncoded();

      //			FileOutputStream copyOut = new FileOutputStream(new File(outputDir, "dg3copy.bin"));
      //			copyOut.write(encodedCopy);
      //			copyOut.flush();
      //			copyOut.close();


      assertNotNull(encodedCopy);
      List<FingerInfo> fingerInfos = dg3.getFingerInfos();
      int fingerInfoCount = fingerInfos.size();

      List<FingerInfo> fingerInfos1 = copy.getFingerInfos();
      int fingerInfoCount1 = fingerInfos1.size();

      assertEquals(fingerInfoCount, fingerInfoCount1);

      int fingerInfoIndex = 0;
      for (FingerInfo fingerInfo: fingerInfos) {
        List<FingerImageInfo> fingerImageInfos = fingerInfo.getFingerImageInfos();
        int fingerImageInfoCount = fingerImageInfos.size();
        FingerInfo fingerInfo1 = fingerInfos1.get(fingerInfoIndex);
        List<FingerImageInfo> fingerImageInfos1 = fingerInfo1.getFingerImageInfos();
        int fingerImageInfoCount1 = fingerImageInfos1.size();
        assertEquals(fingerImageInfoCount, fingerImageInfoCount1);
        int fingerImageInfoIndex = 0;
        for (FingerImageInfo fingerImageInfo: fingerImageInfos) {
          FingerImageInfo fingerImageInfo1 = fingerImageInfos1.get(fingerImageInfoIndex);
          fingerImageInfoIndex ++;
        }
        fingerInfoIndex ++;
      }
    } catch (AccessControlException ace) {
      LOGGER.info("DEBUG: could not access DG3, ignoring this DG3 file");
    } catch(Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testElements() {
    testElements(getTestObjectFromResource());
  }

  public void testElements(DG3File dg3File) {
    FingerInfoTest fingerInfoTest = new FingerInfoTest("DG3FileTest#testElements");
    List<FingerInfo> records = dg3File.getFingerInfos();
    for (FingerInfo fingerInfo: records) {
      fingerInfoTest.testEncodeDecode(fingerInfo);
      fingerInfoTest.testFieldsReasonable(fingerInfo);
      fingerInfoTest.testFieldsSameAfterReconstruct(fingerInfo);
      fingerInfoTest.testReflexiveReconstruct(fingerInfo);
      fingerInfoTest.testMandatorySBHFields(fingerInfo);
      fingerInfoTest.testOptionalSBHFields(fingerInfo);
      fingerInfoTest.testBiometricSubType(fingerInfo);
      fingerInfoTest.testElements(fingerInfo);
    }
  }

  public void testFile(InputStream in) {
    try {
      testDecodeEncode(in);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testImageBytes() {
    try {
      DG3File dg3 = getTestObjectFromResource();
      FingerImageInfo i1 = dg3.getFingerInfos().get(0).getFingerImageInfos().get(0);
      int l1 = i1.getImageLength();
      byte[] b1 = new byte[l1];
      (new DataInputStream(i1.getImageInputStream())).readFully(b1);
      FingerImageInfo i2 = dg3.getFingerInfos().get(1).getFingerImageInfos().get(0);
      int l2 = i2.getImageLength();
      byte[] b2 = new byte[l2];
      (new DataInputStream(i2.getImageInputStream())).readFully(b2);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testImageBytes0() {
    try {
      InputStream inputStream = ResourceUtil.getInputStream(TEST_FILE);
      DG3File dg3 = new DG3File(inputStream);
      List<FingerInfo> fingerInfos = dg3.getFingerInfos();
      for (FingerInfo fingerInfo: fingerInfos) {
        List<FingerImageInfo> fingerImageInfos = fingerInfo.getFingerImageInfos();
        for (FingerImageInfo fingerImageInfo: fingerImageInfos) {
          DataInputStream dataInputStream = new DataInputStream(fingerImageInfo.getImageInputStream());
          byte[] imageBytes = new byte[64]; // FIXME: first check 64 < fingerImageInfo.getImageLength()
          dataInputStream.readFully(imageBytes);
          // LOGGER.info("DEBUG:\n" + Hex.bytesToPrettyString(imageBytes));
        }
      }
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testImageBytes2() {
    try {
      /* Test with byte array input stream as carrier. */

      DG3File dg3 = new DG3File(ResourceUtil.getInputStream(TEST_FILE));

      List<FingerInfo> recordInfos = dg3.getFingerInfos();
      assertEquals(recordInfos.size(), 2);
      FingerInfo record = recordInfos.get(1);
      List<FingerImageInfo> imageInfos = record.getFingerImageInfos();
      assertEquals(imageInfos.size(), 1);
      FingerImageInfo imageInfo = imageInfos.get(0);
      int imgLength = imageInfo.getImageLength();
      assertEquals(imgLength, 15931);

      byte[] imgBytes = new byte[imgLength];

      DataInputStream imgDataIn = new DataInputStream(imageInfo.getImageInputStream());
      imgDataIn.readFully(imgBytes);
      assertEquals("FFA0FFA4003A0907000932D3263C000AE0F31A84010A41EFF1BC010B8E27653F000BE179A4DD00092EFF55D3010AF933D1B6010BF2871F37000A2677DA0CFFA5", Hex.bytesToHexString(imgBytes, 0, 64));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }

  }

  public void testDecodeSecondImage() {
    try {
      DG3File dg3 = new DG3File(ResourceUtil.getInputStream(TEST_FILE));

      int img1Length = dg3.getFingerInfos().get(0).getFingerImageInfos().get(0).getImageLength();
      DataInputStream img1In = new DataInputStream(dg3.getFingerInfos().get(0).getFingerImageInfos().get(0).getImageInputStream());
      byte[] img1Bytes = new byte[img1Length];
      img1In.readFully(img1Bytes);

      int img2Length = dg3.getFingerInfos().get(1).getFingerImageInfos().get(0).getImageLength();
      DataInputStream img2In = new DataInputStream(dg3.getFingerInfos().get(1).getFingerImageInfos().get(0).getImageInputStream());
      byte[] img2Bytes = new byte[img2Length];
      img2In.readFully(img2Bytes);

      // LOGGER.info("DEBUG: img1 (" + img1Bytes.length + ")\n" + Hex.bytesToHexString(img1Bytes, 0, 256));
      // LOGGER.info("DEBUG: img2 (" + img2Bytes.length + ")\n" + Hex.bytesToHexString(img2Bytes, 0, 256));

      assertEquals(Hex.bytesToHexString(img2Bytes, 0, 32), "FFA0FFA4003A0907000932D3263C000AE0F31A84010A41EFF1BC010B8E27653F");
    } catch (Exception e) {
      fail(e.getMessage());
    }
  }

  public void testEncodeDecode1() {
    try {
      /* Fetch the contents of the binary file. */
      byte[] bytes = ResourceUtil.getBytes(TEST_FILE);
      DataInputStream dataIn = new DataInputStream(ResourceUtil.getInputStream(TEST_FILE));
      dataIn.readFully(bytes);
      dataIn.close();

      /* Test with byte array input stream as carrier. */

      DG3File dg3 = new DG3File(new ByteArrayInputStream(bytes));
      int img1Length = dg3.getFingerInfos().get(0).getFingerImageInfos().get(0).getImageLength();
      DataInputStream img1In = new DataInputStream(dg3.getFingerInfos().get(0).getFingerImageInfos().get(0).getImageInputStream());
      byte[] img1Bytes = new byte[img1Length];
      img1In.readFully(img1Bytes);
//      LOGGER.info("DEBUG: img1\n" + Hex.bytesToHexString(img1Bytes, 0, 32));

      int img2Length = dg3.getFingerInfos().get(1).getFingerImageInfos().get(0).getImageLength();
      DataInputStream img2In = new DataInputStream(dg3.getFingerInfos().get(1).getFingerImageInfos().get(0).getImageInputStream());
      byte[] img2Bytes = new byte[img2Length];
      img2In.readFully(img2Bytes);

//      LOGGER.info("DEBUG: img2\n" + Hex.bytesToHexString(img2Bytes, 0, 32));

      byte[] encodedFromByteArrayStream = dg3.getEncoded();

      assertEquals(bytes.length, encodedFromByteArrayStream.length);

      for (int i = 0; i < encodedFromByteArrayStream.length; i++) {
        if (bytes[i] != encodedFromByteArrayStream[i]) {
          LOGGER.info("DEBUG: difference at " + i);
          break;
        }
      }

      //			FileOutputStream out1 = new FileOutputStream("bytes.bin");
      //			out1.write(bytes);
      //			out1.flush();
      //			out1.close();
      //
      //			FileOutputStream out2 = new FileOutputStream("encodedFromByteArrayStream.bin");
      //			out2.write(encodedFromByteArrayStream);
      //			out2.flush();
      //			out2.close();

      assertTrue(Arrays.equals(bytes, encodedFromByteArrayStream));

      /* Same but using file input stream */

      InputStream inputStream = ResourceUtil.getInputStream(TEST_FILE);
      DG3File dg3FromFileStream = new DG3File(inputStream);
      byte[] encodedFromFileStream = dg3FromFileStream.getEncoded();
      assertEquals(bytes.length, encodedFromFileStream.length);
      for (int i = 0; i < encodedFromByteArrayStream.length; i++) {
        if (bytes[i] != encodedFromFileStream[i]) {
          LOGGER.info("DEBUG: difference at " + i);
          break;
        }
      }
      assertTrue(Arrays.equals(bytes, encodedFromFileStream));

    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testEncodeDecode2() {
    try {
      /* Fetch the contents of the binary file. */
      byte[] bytes = ResourceUtil.getBytes(TEST_FILE);
      DataInputStream dataIn = new DataInputStream(ResourceUtil.getInputStream(TEST_FILE));
      dataIn.readFully(bytes);
      dataIn.close();

      /* Test with byte array input stream as carrier. */

      DG3File dg3 = new DG3File(new ByteArrayInputStream(bytes));
      byte[] encodedFromByteArrayStream = dg3.getEncoded();

      DG3File dg3Other = new DG3File(new ByteArrayInputStream(encodedFromByteArrayStream));
      byte[] encodedFromByteArrayStreamOther = dg3Other.getEncoded();

      assertEquals(dg3, dg3Other);

      assertEquals(encodedFromByteArrayStream.length, encodedFromByteArrayStreamOther.length);
      assertTrue(Arrays.equals(encodedFromByteArrayStream, encodedFromByteArrayStreamOther));

    } catch (Exception e) {
      fail(e.getMessage());
    }
  }

  public void testEncodeDecode() {
    try {
      DG3File dg3 = getTestObjectFromResource();
      byte[] dg3Bytes = dg3.getEncoded();
      assertNotNull(dg3Bytes);

      DG3File copy = new DG3File(new ByteArrayInputStream(dg3Bytes));
      byte[] copyBytes = copy.getEncoded();
      assertNotNull(copyBytes);

      //			FileOutputStream out = new FileOutputStream("dg3Bytes.out");
      //			out.write(dg3Bytes);
      //			out.flush();
      //			out.flush();
      //			out.close();
      //
      //			out = new FileOutputStream("copyBytes.out");
      //			out.write(copyBytes);
      //			out.flush();
      //			out.flush();
      //			out.close();

      assertEquals(dg3Bytes.length, copyBytes.length);

      for (int i = 0; i < dg3Bytes.length; i++) {
        if (dg3Bytes[i] != copyBytes[i]) {
          LOGGER.info("DEBUG: difference at " + i);
          break;
        }
      }

      assertTrue(Arrays.equals(dg3Bytes, copyBytes));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testZeroInstanceTestObjectNotEquals() {
    try {
      DG3File dg3 = new DG3File(new LinkedList<FingerInfo>());
      byte[] dg3Bytes = dg3.getEncoded();
      assertNotNull(dg3Bytes);

      DG3File anotherDG3 = new DG3File(new LinkedList<FingerInfo>());
      byte[] anotherDG3Bytes = anotherDG3.getEncoded();
      assertNotNull(anotherDG3Bytes);

      assertFalse(Arrays.equals(dg3Bytes, anotherDG3Bytes));

      DG3File copy = new DG3File(new ByteArrayInputStream(dg3Bytes));
      byte[] copyBytes = copy.getEncoded();
      assertNotNull(copyBytes);

      assertFalse(Arrays.equals(dg3Bytes, copyBytes));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testCreate() {
    DG3File dg3 = createTestObject();
    byte[] header = new byte[256];
    System.arraycopy(dg3.getEncoded(), 0, header, 0, header.length);
//    LOGGER.info(Hex.bytesToPrettyString(header));
  }

  public void testFromBin() {
    try {
      InputStream inputStream = ResourceUtil.getInputStream(TEST_FILE);
      DG3File dg3 = new DG3File(inputStream);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public static DG3File createTestObject() {
    try {
      FingerInfo fingerInfo1 = FingerInfoTest.createSingleRightIndexFingerTestObject();
      //			FingerInfo fingerInfo2 = FingerInfoTest.createTestObject();
      List<FingerInfo> fingerInfos = Arrays.asList(new FingerInfo[] { fingerInfo1, /* fingerInfo2 */ });
      DG3File dg3 = new DG3File(fingerInfos);
      return dg3;
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());

      return null;
    }
  }

  public static DG3File getTestObjectFromResource() {
    try {
      InputStream in = ResourceUtil.getInputStream(TEST_FILE);
      DG3File dg3 = new DG3File(in);
      return dg3;
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      return null;
    }
  }
}
