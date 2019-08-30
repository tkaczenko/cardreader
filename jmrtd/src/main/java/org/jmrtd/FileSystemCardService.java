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
 * $Id: FileSystemCardService.java 1781 2018-05-25 11:41:48Z martijno $
 */

package org.jmrtd;

import net.sf.scuba.smartcards.CardFileInputStream;
import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;

/**
 * A card service that acts as a (file identifier indexed) file system.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1781 $
 */
public abstract class FileSystemCardService extends CardService {

  /**
   * Returns an input stream to access the file indicated by the file identifier.
   *
   * @param fid the file identifier
   *
   * @return a stream to read from
   *
   * @throws CardServiceException on error creating the stream
   */
  public abstract CardFileInputStream getInputStream(short fid) throws CardServiceException;
}
