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
 * $Id: FaceImageInfoTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.lds;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.imageio.ImageIO;

import org.jmrtd.lds.ImageInfo;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.jmrtd.lds.iso19794.FaceImageInfo.EyeColor;
import org.jmrtd.lds.iso19794.FaceImageInfo.FeaturePoint;

import junit.framework.TestCase;
import net.sf.scuba.data.Gender;
import net.sf.scuba.util.Hex;

public class FaceImageInfoTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public FaceImageInfoTest(String name) {
    super(name);
  }

  public void testToString() {
    FaceImageInfo imageInfo = createNonEmptyTestObject();
    try {
      assertNotNull(imageInfo);
      String asString = imageInfo.toString();
      assertNotNull(asString);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testNonNullEncoded() {
    FaceImageInfo imageInfo = createNonEmptyTestObject();
    assertNotNull(imageInfo);
    byte[] encoded = imageInfo.getEncoded();
    assertNotNull(encoded);
  }

  public void testEncodeDecode() {
    testEncodeDecode(createNonEmptyTestObject());
  }

  public void testEncodeDecode(FaceImageInfo original) {
    try {
      byte[] encoded = original.getEncoded();
      assertNotNull(encoded);
      ByteArrayInputStream in = new ByteArrayInputStream(encoded);
      FaceImageInfo copy = new FaceImageInfo(in);
      assertEquals(original, copy);
      byte[] encodedCopy = copy.getEncoded();
      assertNotNull(encodedCopy);
      assertEquals(Hex.bytesToHexString(encoded), Hex.bytesToHexString(encodedCopy));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testNumExtractImageOnce() {
    FaceImageInfo imageInfo = createNonEmptyTestObject(50, 50);
    testExtractImage(imageInfo, 50, 50);
  }

  public void testNumExtractImage() {
    for (int width = 100; width < 1000; width += 200) {
      for (int height = 100; height < 1000; height += 200) {
        FaceImageInfo imageInfo = createNonEmptyTestObject(width, height);
        testExtractImage(imageInfo, width, height);
      }
    }
  }

  public void testExtractImage(FaceImageInfo imageInfo, int expectedWidth, int expectedHeight) {
    try {
      InputStream imageInputStream = imageInfo.getImageInputStream();
      int imageLength = imageInfo.getImageLength();
      assertTrue(imageLength >= 0);
      String imageMimeType = imageInfo.getMimeType();
      assertNotNull(imageMimeType);
      assertTrue(imageMimeType.toLowerCase().startsWith("image"));
      imageInputStream.close();
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testValidType() {
    FaceImageInfo portraitInfo = createTestObject();
    testValidType(portraitInfo);
  }

  public void testValidType(FaceImageInfo imageInfo) {
    int type = imageInfo.getType();
    assertEquals(type, ImageInfo.TYPE_PORTRAIT);
  }

  public void testLength() {
    FaceImageInfo faceImageInfo = createTestObject();
    int imageLength = faceImageInfo.getImageLength();
    int recordLength = (int)faceImageInfo.getRecordLength();
    assertTrue(imageLength < recordLength);
  }

  public static FaceImageInfo createTestObject() {
    return createNonEmptyTestObject(300, 400);
  }

  public static FaceImageInfo createNonEmptyTestObject() {
    return createNonEmptyTestObject(1, 1);
  }

  public void testCreateAndExtract() {
    try {
      FaceImageInfo imageInfo = createNonEmptyTestObject();
      DataInputStream imageInputStream = new DataInputStream(imageInfo.getImageInputStream());
      int imageLength = imageInfo.getImageLength();
      byte[] imageBytes = new byte[imageLength];
      imageInputStream.readFully(imageBytes);
      imageInputStream.close();
//      LOGGER.info("DEBUG: imageBytes.length = " + imageBytes.length);
    } catch (IOException e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public static FaceImageInfo createNonEmptyTestObject(int width, int height) {
    try {
      byte[] imageBytes = createTrivialJPEGBytes(width, height);
      Gender gender = Gender.UNSPECIFIED;
      EyeColor eyeColor = EyeColor.UNSPECIFIED;
      int hairColor = FaceImageInfo.HAIR_COLOR_UNSPECIFIED;
      int featureMask = 0;
      short expression = FaceImageInfo.EXPRESSION_UNSPECIFIED;
      int[] poseAngle = { 0, 0, 0 };
      int[] poseAngleUncertainty = { 0, 0, 0 };
      int faceImageType = FaceImageInfo.FACE_IMAGE_TYPE_FULL_FRONTAL;
      int colorSpace = 0x00;
      int sourceType = FaceImageInfo.SOURCE_TYPE_UNSPECIFIED;
      int deviceType = 0x0000;
      int quality = 0x0000;
      int imageDataType = FaceImageInfo.IMAGE_DATA_TYPE_JPEG;
      FeaturePoint[] featurePoints = new FeaturePoint[0];
      FaceImageInfo imageInfo = new FaceImageInfo(
          gender, eyeColor, hairColor,
          featureMask,
          expression,
          poseAngle, poseAngleUncertainty,
          faceImageType,
          colorSpace,
          sourceType,
          deviceType,
          quality,
          featurePoints,
          width, height,
          new ByteArrayInputStream(imageBytes), imageBytes.length, imageDataType);
      return imageInfo;
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      return null;
    }
  }

  private static byte[] createTrivialJPEGBytes(int width, int height) {
    try {
      BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      ImageIO.write(image, "jpg", out);
      out.flush();
      byte[] bytes = out.toByteArray();
      return bytes;
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
      return null;
    }
  }
}
