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
 * $Id: DG7FileTest.java 1798 2018-10-09 10:27:22Z martijno $
 */

package org.jmrtd.test.lds;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.imageio.ImageIO;

import org.jmrtd.lds.DisplayedImageInfo;
import org.jmrtd.lds.ImageInfo;
import org.jmrtd.lds.icao.DG7File;

import junit.framework.TestCase;
import net.sf.scuba.util.Hex;

public class DG7FileTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public DG7FileTest(String name) {
    super(name);
  }

  public void testToString() {
    testToString(createEmptyTestObject(), "DG7File []");
  }

  public void testToString(DG7File dg7File, String expectedResult) {
    try {
      assertNotNull(dg7File);
      assertEquals(dg7File.toString(), expectedResult);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testType() {
    testType(createEmptyTestObject());

    DG7File dg7 = createNumTestObject(1);
    testType(dg7);
  }

  public void testType(DG7File dg7File) {
    try {
      assertNotNull(dg7File);
      List<DisplayedImageInfo> displayedImageInfos = dg7File.getImages();
      for (DisplayedImageInfo displayedImageInfo: displayedImageInfos) {
        assertEquals(displayedImageInfo.getType(), DisplayedImageInfo.TYPE_SIGNATURE_OR_MARK);
      }
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testNonNullEncoded() {
    DG7File dg7File = createEmptyTestObject();
    assertNotNull(dg7File);
    byte[] encoded = dg7File.getEncoded();
    assertNotNull(encoded);
  }

  public void testReflexive() {
    testEncodeDecode(createEmptyTestObject());
  }

  public void testNum() {
    for (int n = 1; n < 10; n++) {
      DG7File dg7File = createNumTestObject(n);
      assertNotNull(dg7File);
      List<DisplayedImageInfo> imageInfos = dg7File.getImages();
      assertNotNull(imageInfos);
      assertEquals(imageInfos.size(), n);
      testEncodeDecode(dg7File);
      testElements(dg7File);
    }
  }

  public void testElements(DG7File dg7File) {
    assertNotNull(dg7File);
    List<DisplayedImageInfo> imageInfos = dg7File.getImages();
    for (DisplayedImageInfo imageInfo: imageInfos) {
      assertNotNull(imageInfo);
    }
  }

  public void testEncodeDecode(DG7File dg7File) {
    try {
      byte[] encoded = dg7File.getEncoded();
      assertNotNull(encoded);
      ByteArrayInputStream in = new ByteArrayInputStream(encoded);
      DG7File copy = new DG7File(in);
      assertEquals(dg7File, copy);
      byte[] encodedCopy = copy.getEncoded();
      assertNotNull(encodedCopy);
      assertEquals(Hex.bytesToHexString(encoded), Hex.bytesToHexString(encodedCopy));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testCreate() {
    try {
      DG7File dg7 = createTestObject();
      byte[] header = new byte[256];
      System.arraycopy(dg7.getEncoded(), 0, header, 0, header.length);
//      LOGGER.info(Hex.bytesToPrettyString(header));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public static DG7File createEmptyTestObject() {
    List<DisplayedImageInfo> images = new LinkedList<DisplayedImageInfo>();
    return new DG7File(images);
  }

  public static DG7File createNumTestObject(int n) {
    List<DisplayedImageInfo> images = new LinkedList<DisplayedImageInfo>();
    for (int i = 0; i < n; i++) {
      byte[] imageBytes = new byte[0];
      DisplayedImageInfo imageInfo = new DisplayedImageInfo(ImageInfo.TYPE_SIGNATURE_OR_MARK, imageBytes);
      images.add(imageInfo);
    }
    DG7File dg7File = new DG7File(images);
    return dg7File;
  }

  public static DG7File createTestObject() {
    byte[] image = createTrivialJPEGBytes(958, 208);
    DisplayedImageInfo imageInfo = new DisplayedImageInfo(ImageInfo.TYPE_SIGNATURE_OR_MARK, image);
    DG7File dg7File = new DG7File(Arrays.asList(new DisplayedImageInfo[] { imageInfo }));
    return dg7File;
  }

  public void testFile(InputStream in) {
    try {
      testEncodeDecode(new DG7File(in));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
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
