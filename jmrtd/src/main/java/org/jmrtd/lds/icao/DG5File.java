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
 * $Id: DG5File.java 1751 2018-01-15 15:35:45Z martijno $
 */

package org.jmrtd.lds.icao;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.jmrtd.lds.DisplayedImageDataGroup;
import org.jmrtd.lds.DisplayedImageInfo;

/**
 * File structure for the EF_DG5 file.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1751 $
 */
public class DG5File extends DisplayedImageDataGroup {

  private static final long serialVersionUID = 923840683207218244L;

  /**
   * Constructs a new file from a list of displayed images.
   *
   * @param images the displayed images, all of which should be of type <i>Portrait</i>
   */
  public DG5File(List<DisplayedImageInfo> images) {
    super(EF_DG5_TAG, images, DisplayedImageInfo.DISPLAYED_PORTRAIT_TAG);
  }

  /**
   * Constructs a new file from binary representation.
   *
   * @param inputStream an input stream
   *
   * @throws IOException on error reading input stream
   */
  public DG5File(InputStream inputStream) throws IOException {
    super(EF_DG5_TAG, inputStream);
  }
}
