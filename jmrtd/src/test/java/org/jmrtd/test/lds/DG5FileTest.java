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
 * $Id: DG5FileTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.lds;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.lds.DisplayedImageInfo;
import org.jmrtd.lds.ImageInfo;
import org.jmrtd.lds.icao.DG5File;

import junit.framework.TestCase;

public class DG5FileTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public void testDG5File() {
    byte[] imageBytes = { 0x01, 0x02 };
    DisplayedImageInfo image = new DisplayedImageInfo(ImageInfo.TYPE_PORTRAIT, imageBytes);
    List<DisplayedImageInfo> images = Arrays.asList(new DisplayedImageInfo[] { image });
    DG5File dg5File = new DG5File(images);

    assertEquals(DG5File.EF_DG5_TAG, dg5File.getTag());
    assertEquals(new ArrayList<DisplayedImageInfo>(images), dg5File.getImages());

    byte[] expectedEncoded = { 0x65, 0x08, 0x02, 0x01, 0x01, 0x5F, 0x40, 0x02, 0x01, 0x02 };

    assertTrue(Arrays.equals(expectedEncoded, dg5File.getEncoded()));
  }

  public void testDG5FileDecode() {
    try {
      byte[] encoded = { 0x65, 0x08, 0x02, 0x01, 0x01, 0x5F, 0x40, 0x02, 0x01, 0x02 };
      DG5File dg5File = new DG5File(new ByteArrayInputStream(encoded));
      assertEquals(DG5File.EF_DG5_TAG, dg5File.getTag());

      byte[] imageBytes = { 0x01, 0x02 };
      DisplayedImageInfo image = new DisplayedImageInfo(ImageInfo.TYPE_PORTRAIT, imageBytes);
      List<DisplayedImageInfo> expectedImages = Arrays.asList(new DisplayedImageInfo[] { image });
      assertEquals(new ArrayList<DisplayedImageInfo>(expectedImages), dg5File.getImages());
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());

    }
  }

  public void testDG5FileSerializable() {
    try {
      byte[] imageBytes = { 0x01, 0x02 };
      DisplayedImageInfo image = new DisplayedImageInfo(ImageInfo.TYPE_PORTRAIT, imageBytes);
      List<DisplayedImageInfo> images = Arrays.asList(new DisplayedImageInfo[] { image });
      DG5File dg5File = new DG5File(images);

      ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
      try {
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(dg5File);
        objectOutputStream.flush();
        objectOutputStream.close();
        byte[] encoded = byteArrayOutputStream.toByteArray();

        ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(encoded));
        Object decoded = objectInputStream.readObject();

        assertNotNull(decoded);
        assertTrue(decoded instanceof DG5File);
        assertEquals(dg5File, decoded);
      } finally {
        try {
          byteArrayOutputStream.close();
        } catch (IOException ioe) {
          LOGGER.log(Level.FINE, "Error closing stream", ioe);
        }
      }
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }
}
