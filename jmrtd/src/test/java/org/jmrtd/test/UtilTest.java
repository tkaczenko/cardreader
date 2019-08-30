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
 * $Id: UtilTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.Util;

import junit.framework.TestCase;
import net.sf.scuba.util.Hex;

/**
 * Tests some of the utility functions.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1813 $
 *
 * @since 0.6.2
 */
public class UtilTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public void testPadding() {
    testPadding(3, 64);
    testPadding(31, 64);
    testPadding(32, 64);
    testPadding(58, 64);
    testPadding(63, 64);
    testPadding(64, 64);
    testPadding(65, 64);
    testPadding(65, 128);
    testPadding(127, 128);
  }

  public void testPadding(int arraySize, int blockSize) {
    try {
      Random random = new Random();
      byte[] bytes = new byte[arraySize];
      random.nextBytes(bytes);

      byte[] paddedBytes = Util.pad(bytes, blockSize);
      assertNotNull(paddedBytes);
      assertTrue(paddedBytes.length >= bytes.length);
      assertTrue(isPrefixOf(bytes, paddedBytes));

      byte[] unpaddedPaddedBytes = Util.unpad(paddedBytes);
      assertTrue(Arrays.equals(bytes, unpaddedPaddedBytes));

    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
    }
  }

  public void testPartition() {
    for (int dataSize = 23; dataSize < 987; dataSize++) {
      for (int segmentSize = 13; segmentSize < 63; segmentSize ++) {
        testPartition(dataSize, segmentSize);
      }
    }
  }

  public void testPartition(int dataSize, int segmentSize) {
    Random random = new Random();
    byte[] data = new byte[dataSize];
    random.nextBytes(data);
    List<byte[]> segments = Util.partition(segmentSize, data);

    /* This should be approximately true. */
    assertTrue(segmentSize * (segments.size() - 1) <= dataSize);
    assertTrue(segmentSize * segments.size() >= dataSize);

    List<Boolean> isLasts = new ArrayList<Boolean>(segments.size());
    int index = 0;
    for (byte[] segment: segments) {
      boolean isLast = ++index >= segments.size();
      isLasts.add(isLast);
    }
    for (int i = 0; i < segments.size() - 1; i++) {
      assertFalse(isLasts.get(i));
    }
    assertTrue(isLasts.get(segments.size() - 1));
  }

  public void testStripLeadingZeroes() {
    byte[] example = { 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04 };
    byte[] stripped = Util.stripLeadingZeroes(example);
    assertTrue(stripped[0] != 0x00);
    assertTrue(Arrays.equals(new byte[] { 0x01, 0x02, 0x03, 0x04 }, stripped));
  }

  public void testBigIntegerI2OSStripLeadingZeroes() {
    for (long i = 0; i < 66666; i++) {
      BigInteger bigInteger = BigInteger.valueOf(i);
      byte[] bigIBytes = bigInteger.toByteArray();
      byte[] os = Util.i2os(bigInteger);
      assertTrue(i  + ": " +  Hex.bytesToHexString(bigIBytes) + ", " + Hex.bytesToHexString(os), Arrays.equals(os, Util.stripLeadingZeroes(bigIBytes)));
    }
  }

  private static boolean isPrefixOf(byte[] bytes, byte[] paddedBytes) {
    if (bytes == null || paddedBytes == null) {
      throw new IllegalArgumentException();
    }

    if (bytes.length > paddedBytes.length) {
      return false;
    }

    for (int i = 0; i < bytes.length; i++) {
      if (paddedBytes[i] != bytes[i]) {
        return false;
      }
    }

    return true;
  }
}
