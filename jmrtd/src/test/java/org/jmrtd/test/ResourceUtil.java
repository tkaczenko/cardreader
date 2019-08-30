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
 * $Id: ResourceUtil.java 1751 2018-01-15 15:35:45Z martijno $
 */

package org.jmrtd.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.logging.Logger;

public class ResourceUtil {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public static byte[] getBytes(String resource) throws IOException {
    InputStream is = getInputStream(resource);
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    int nRead;
    byte[] data = new byte[16384];
    while ((nRead = is.read(data, 0, data.length)) != -1) {
      buffer.write(data, 0, nRead);
    }
    buffer.flush();
    return buffer.toByteArray();
  }

  public static InputStream getInputStream(String resource) {
    InputStream inputStream = null;
    URL url = ResourceUtil.class.getResource(resource);
    /* NOTE: getResourceAsStream() is preferred over openConnection on URL. */
    inputStream = ResourceUtil.class.getResourceAsStream(resource);
    return inputStream;
  }
}
