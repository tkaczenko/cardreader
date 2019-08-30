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
 * $Id: DG6FileTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.lds;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.lds.DisplayedImageInfo;
import org.jmrtd.lds.ImageInfo;
import org.jmrtd.lds.icao.DG6File;

import junit.framework.TestCase;

public class DG6FileTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public void testDG6File() {
    try {

      byte[] encoded = { 0x66, 0x08, 0x02, 0x01, 0x01, 0x5F, 0x40, 0x02, 0x01, 0x02 }; // NOTE: Uses 5F40, i.e. portrait. Not sure if DG6 is supposed to hold portrait images...
      DG6File dg6File = new DG6File(new ByteArrayInputStream(encoded));

      assertEquals(DG6File.EF_DG6_TAG, dg6File.getTag());

      byte[] imageBytes = { 0x01, 0x02 };
      DisplayedImageInfo image = new DisplayedImageInfo(ImageInfo.TYPE_PORTRAIT, imageBytes);
      List<DisplayedImageInfo> expectedImages = Arrays.asList(new DisplayedImageInfo[] { image });

      assertEquals(expectedImages, dg6File.getImages());

    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }
}
