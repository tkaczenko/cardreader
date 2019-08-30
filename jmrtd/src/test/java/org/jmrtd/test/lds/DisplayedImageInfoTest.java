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
 * $Id: DisplayedImageInfoTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.lds;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.imageio.ImageIO;

import org.jmrtd.lds.DisplayedImageInfo;
import org.jmrtd.lds.ImageInfo;

import junit.framework.TestCase;
import net.sf.scuba.util.Hex;

public class DisplayedImageInfoTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public DisplayedImageInfoTest(String name) {
    super(name);
  }

  public void testToString() {
    testToString(createNonEmptyTestObject(), "DisplayedImageInfo [type: Signature or usual mark, size: ");
  }

  public void testToString(DisplayedImageInfo imageInfo, String expectedResult) {
    try {
      assertNotNull(imageInfo);
      String asString = imageInfo.toString();
      assertNotNull(asString);
      assertTrue("String: \"" + asString + "\"", asString.startsWith(expectedResult));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testNonNullEncoded() {
    DisplayedImageInfo imageInfo = createNonEmptyTestObject();
    assertNotNull(imageInfo);
    byte[] encoded = imageInfo.getEncoded();
    assertNotNull(encoded);
  }

  public void testEncodeDecode() {
    testEncodeDecode(createNonEmptyTestObject());
  }

  public void testEncodeDecode(DisplayedImageInfo original) {
    try {
      byte[] encoded = original.getEncoded();
      assertNotNull(encoded);
      ByteArrayInputStream in = new ByteArrayInputStream(encoded);
      DisplayedImageInfo copy = new DisplayedImageInfo(in);
      assertEquals(original.getType(), copy.getType());
      assertEquals(original, copy);
      byte[] encodedCopy = copy.getEncoded();
      assertNotNull(encodedCopy);
      assertEquals(Hex.bytesToHexString(encoded), Hex.bytesToHexString(encodedCopy));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testValidType() {
    DisplayedImageInfo signatureInfo = createNonEmptyTestObject(ImageInfo.TYPE_SIGNATURE_OR_MARK, 800, 266);
    testValidType(signatureInfo);

    DisplayedImageInfo portraitInfo = createNonEmptyTestObject(ImageInfo.TYPE_PORTRAIT, 300, 400);
    testValidType(portraitInfo);
  }

  public void testValidType(DisplayedImageInfo imageInfo) {
    int type = imageInfo.getType();
    assertTrue(type == ImageInfo.TYPE_PORTRAIT || type == ImageInfo.TYPE_SIGNATURE_OR_MARK);
  }

  public static DisplayedImageInfo createNonEmptyTestObject() {
    return createNonEmptyTestObject(ImageInfo.TYPE_SIGNATURE_OR_MARK, 1, 1);
  }

  public static DisplayedImageInfo createNonEmptyTestObject(int type, int width, int height) {
    byte[] imageBytes = createTrivialJPEGBytes(width, height);
    DisplayedImageInfo imageInfo = new DisplayedImageInfo(type, imageBytes);
    return imageInfo;
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
