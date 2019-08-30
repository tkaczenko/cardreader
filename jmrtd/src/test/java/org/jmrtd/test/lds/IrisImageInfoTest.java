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
 * $Id: IrisImageInfoTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.lds;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.imageio.ImageIO;

import org.jmrtd.lds.iso19794.IrisImageInfo;
import org.jmrtd.lds.iso19794.IrisInfo;

import junit.framework.TestCase;

public class IrisImageInfoTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public void testToString() {
    try {
      IrisImageInfo info = createTestObject();
      assertNotNull(info);
      String asString = info.toString();
      assertNotNull(asString);
      assertTrue(asString.startsWith("IrisImageInfo"));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testLength() {
    IrisImageInfo irisImageInfo = createTestObject();
    int imageLength = irisImageInfo.getImageLength();
    int recordLength = (int)irisImageInfo.getRecordLength();
    assertTrue(imageLength < recordLength);
  }

  public static IrisImageInfo createTestObject() {
    try {
      BufferedImage image = new BufferedImage(300, 200, BufferedImage.TYPE_BYTE_GRAY);
      ByteArrayOutputStream encodedImageOut = new ByteArrayOutputStream();
      ImageIO.write(image, "jpg", encodedImageOut);
      encodedImageOut.flush();
      byte[] imageBytes = encodedImageOut.toByteArray();
      IrisImageInfo irisImageInfo = new IrisImageInfo(1, image.getWidth(), image.getHeight(), new ByteArrayInputStream(imageBytes), imageBytes.length, IrisInfo.IMAGEFORMAT_MONO_JPEG);
      return irisImageInfo;
    } catch (IOException e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
      return null;
    }
  }
}
