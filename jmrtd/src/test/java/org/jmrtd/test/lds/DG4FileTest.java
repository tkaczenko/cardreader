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
 * $Id: DG4FileTest.java 1799 2018-10-30 16:25:48Z martijno $
 */

package org.jmrtd.test.lds;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.AccessControlException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.imageio.ImageIO;

import org.jmrtd.lds.icao.DG4File;
import org.jmrtd.lds.iso19794.IrisBiometricSubtypeInfo;
import org.jmrtd.lds.iso19794.IrisImageInfo;
import org.jmrtd.lds.iso19794.IrisInfo;
import org.jmrtd.test.ResourceUtil;

import junit.framework.TestCase;

public class DG4FileTest extends TestCase {

  public static final String TEST_FILE = "/lds/bsi2008/Datagroup4.bin";

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public DG4FileTest(String name) {
    super(name);
  }

  public void testConstruct() {
    try {
      DG4File dg4 = new DG4File(Arrays.asList(new IrisInfo[] { }));
      assertNotNull(dg4.getIrisInfos());
      assertTrue(dg4.getIrisInfos().isEmpty());
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testReflexive() {
    DG4File dg4 = createTestObject();
    testReflexive(dg4);

    dg4 = getTestObject();
    testReflexive(dg4);
  }

  public void testReflexive(DG4File dg4) {
    try {
      byte[] bytes = dg4.getEncoded();
      InputStream inputStream = new ByteArrayInputStream(bytes);
      DG4File copy = new DG4File(inputStream);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testEncodeDecode() {
    DG4File dg4 = getTestObject();
    testEncodeDecode(dg4);

    dg4 = createTestObject();
    testEncodeDecode(dg4);
  }

  public void testEncodeDecode(DG4File dg4) {
    try {
      byte[] dg4Bytes = dg4.getEncoded();
      assertNotNull(dg4Bytes);

      DG4File copy = new DG4File(new ByteArrayInputStream(dg4Bytes));
      byte[] copyBytes = copy.getEncoded();
      assertNotNull(copyBytes);

      assertTrue(Arrays.equals(dg4Bytes, copyBytes));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testZeroInstanceTestObjectNotEquals() {
    try {
      DG4File dg4 = new DG4File(new LinkedList<IrisInfo>());
      byte[] dg4Bytes = dg4.getEncoded();
      assertNotNull(dg4Bytes);

      DG4File anotherDG4 = new DG4File(new LinkedList<IrisInfo>());
      byte[] anotherDG4Bytes = anotherDG4.getEncoded();
      assertNotNull(anotherDG4Bytes);

      assertFalse(Arrays.equals(dg4Bytes, anotherDG4Bytes));

      DG4File copy = new DG4File(new ByteArrayInputStream(dg4Bytes));
      byte[] copyBytes = copy.getEncoded();
      assertNotNull(copyBytes);

      assertFalse(Arrays.equals(dg4Bytes, copyBytes));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testFile() {
    try {
      DG4File dg4 = getTestObject();
      List<IrisInfo> recordInfos = dg4.getIrisInfos();
      int recordCount = recordInfos.size();
      int recordNumber = 1;
//      LOGGER.info("DEBUG: Number of iris records = " + recordCount);
      for (IrisInfo record: recordInfos) {
        List<IrisBiometricSubtypeInfo> subtypeInfos = record.getIrisBiometricSubtypeInfos();
        int subtypeInfoCount = subtypeInfos.size();
//        LOGGER.info("DEBUG: Number of subtypes in iris record " + recordNumber + " is " + subtypeInfoCount);
        int imageInfoNumber = 1;
        for (IrisBiometricSubtypeInfo subtypeInfo: subtypeInfos) {
          List<IrisImageInfo> imageInfos = subtypeInfo.getIrisImageInfos();
          int imageInfoCount = imageInfos.size();
//          LOGGER.info("DEBUG: Number of image infos in iris subtype record " + imageInfoNumber + " is " + imageInfoCount);
          for (IrisImageInfo imageInfo: imageInfos) {
            int length = imageInfo.getImageLength();
            byte[] bytes = new byte[length];
            DataInputStream dataIn = new DataInputStream(imageInfo.getImageInputStream());
            dataIn.readFully(bytes);
          }
          subtypeInfoCount ++;
        }
        recordNumber ++;
      }
    } catch (AccessControlException ace) {
      LOGGER.log(Level.WARNING, "Exception", ace);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public static DG4File createTestObject() {
    try {
      BufferedImage image = new BufferedImage(300, 200, BufferedImage.TYPE_INT_RGB);
      ByteArrayOutputStream imageOut = new ByteArrayOutputStream();
      ImageIO.write(image, "jpg", imageOut);
      byte[] imageBytes = imageOut.toByteArray();

      int imageFormat = IrisInfo.IMAGEFORMAT_RGB_JPEG;
      IrisImageInfo irisImageInfo = new IrisImageInfo(0, 300, 200, new ByteArrayInputStream(imageBytes), imageBytes.length, IrisInfo.IMAGEFORMAT_RGB_JPEG);

      int biometricSubtype = IrisBiometricSubtypeInfo.EYE_UNDEF;
      IrisBiometricSubtypeInfo irisBiometricSubtypeInfo = new IrisBiometricSubtypeInfo(biometricSubtype, imageFormat, Arrays.asList(new IrisImageInfo[] { irisImageInfo }));

      int captureDeviceId = IrisInfo.CAPTURE_DEVICE_UNDEF;
      int horizontalOrientation = IrisInfo.ORIENTATION_UNDEF;
      int verticalOrientation = IrisInfo.ORIENTATION_UNDEF;
      int scanType = IrisInfo.SCAN_TYPE_UNDEF;
      int irisOcclusion = IrisInfo.IROCC_UNDEF;
      int occlusionFilling = IrisInfo.IROCC_UNDEF;
      int boundaryExtraction = IrisInfo.IRBNDY_UNDEF;
      int irisDiameter = 167;
      int rawImageWidth = 300;
      int rawImageHeight = 200;
      int intensityDepth = 8;
      int imageTransformation = IrisInfo.TRANS_UNDEF;
      byte[] deviceUniqueId = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
      IrisInfo irisInfo = new IrisInfo(
          captureDeviceId,
          horizontalOrientation,
          verticalOrientation,
          scanType,
          irisOcclusion,
          occlusionFilling,
          boundaryExtraction,
          irisDiameter,
          imageFormat,
          rawImageWidth,
          rawImageHeight,
          intensityDepth,
          imageTransformation,
          deviceUniqueId,
          Arrays.asList(new IrisBiometricSubtypeInfo[] { irisBiometricSubtypeInfo }));
      DG4File dg4 = new DG4File(Arrays.asList(new IrisInfo[] { irisInfo }));
      dg4.addIrisInfo(IrisInfoTest.createTestObject());
      return dg4;
    } catch (IOException ioe) {
      fail(ioe.getMessage());
      return null;
    }
  }

  public static DG4File getTestObject() {
    try {
      InputStream in = ResourceUtil.getInputStream(TEST_FILE);
      DG4File dg4 = new DG4File(in);
      return dg4;
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      return null;
    }
  }
}
