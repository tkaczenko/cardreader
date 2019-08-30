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
 * $Id: IrisBiometricSubtypeInfoTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.lds;

import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.lds.iso19794.IrisBiometricSubtypeInfo;
import org.jmrtd.lds.iso19794.IrisImageInfo;
import org.jmrtd.lds.iso19794.IrisInfo;

import junit.framework.TestCase;

public class IrisBiometricSubtypeInfoTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public void testCreate() {
    IrisBiometricSubtypeInfo irisSubtypeInfo = createTestObject();
    int subtypeId = irisSubtypeInfo.getBiometricSubtype();
    assertTrue(subtypeId == IrisBiometricSubtypeInfo.EYE_LEFT
        || subtypeId == IrisBiometricSubtypeInfo.EYE_RIGHT
        || subtypeId == IrisBiometricSubtypeInfo.EYE_UNDEF);
    int imageFormat = irisSubtypeInfo.getImageFormat();
    assertTrue(imageFormat >= 0);
  }

  public void testToString() {
    try {
      IrisBiometricSubtypeInfo info = createTestObject();
      assertNotNull(info);
      String asString = info.toString();
      assertNotNull(asString);
      assertTrue(asString.startsWith("IrisBiometricSubtypeInfo"));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public static IrisBiometricSubtypeInfo createTestObject() {
    IrisImageInfo irisImageInfo = IrisImageInfoTest.createTestObject();
    List<IrisImageInfo> irisImageInfos = Arrays.asList(new IrisImageInfo[] { irisImageInfo });
    IrisBiometricSubtypeInfo irisSubtypeInfo = new IrisBiometricSubtypeInfo(IrisBiometricSubtypeInfo.EYE_LEFT, IrisInfo.IMAGEFORMAT_MONO_JPEG, irisImageInfos);
    return irisSubtypeInfo;
  }

}
