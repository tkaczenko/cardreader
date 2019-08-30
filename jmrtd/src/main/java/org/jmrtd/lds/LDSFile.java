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
 * $Id: LDSFile.java 1764 2018-02-19 16:19:25Z martijno $
 */

package org.jmrtd.lds;

/**
 * LDS element at file level.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1764 $
 */
public interface LDSFile extends LDSElement {

  /* NOTE: In EAC 1.11 documents there is also the CVCA file that has no tag. */

  /** ICAO tag for document index (COM). */
  public static final int EF_COM_TAG = 0x60;

  /** ICAO data group tag for DG1. */
  public static final int EF_DG1_TAG = 0x61;

  /** ICAO data group tag for DG2. */
  public static final int EF_DG2_TAG = 0x75;

  /** ICAO data group tag for DG3. */
  public static final int EF_DG3_TAG = 0x63;

  /** ICAO data group tag for DG4. */
  public static final int EF_DG4_TAG = 0x76;

  /** ICAO data group tag for DG5. */
  public static final int EF_DG5_TAG = 0x65;

  /** ICAO data group tag for DG6. */
  public static final int EF_DG6_TAG = 0x66;

  /** ICAO data group tag for DG7. */
  public static final int EF_DG7_TAG = 0x67;

  /** ICAO data group tag for DG8. */
  public static final int EF_DG8_TAG = 0x68;

  /** ICAO data group tag for DG9. */
  public static final int EF_DG9_TAG = 0x69;

  /** ICAO data group tag for DG10. */
  public static final int EF_DG10_TAG = 0x6A;

  /** ICAO data group tag for DG11. */
  public static final int EF_DG11_TAG = 0x6B;

  /** ICAO data group tag for DG12. */
  public static final int EF_DG12_TAG = 0x6C;

  /** ICAO data group tag for DG13. */
  public static final int EF_DG13_TAG = 0x6D;

  /** ICAO data group tag for DG14. */
  public static final int EF_DG14_TAG = 0x6E;

  /** ICAO data group tag for DG15. */
  public static final int EF_DG15_TAG = 0x6F;

  /** ICAO data group tag for DG16. */
  public static final int EF_DG16_TAG = 0x70;

  /** ICAO tag for document security index (SOd). */
  public static final int EF_SOD_TAG = 0x77;

  /*
   * FIXME: Note that this is not necessarily the total length of the file:
   * For TLV files this gives the length of the value. -- MO
   */
  /**
   * Returns the length of this file.
   *
   * @return the length of this file
   */
  int getLength();
}
