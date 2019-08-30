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
 * $Id: CVCAFileTest.java 1751 2018-01-15 15:35:45Z martijno $
 */

package org.jmrtd.test.lds;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Arrays;

import org.jmrtd.lds.CVCAFile;

import junit.framework.TestCase;

public class CVCAFileTest extends TestCase {

  public void test1() {
    String name1 = "CAReference00001";
    CVCAFile f = new CVCAFile(name1, null);
    assertEquals(name1, f.getCAReference().getName());
    assertEquals(null, f.getAltCAReference());
  }

  public void test2() {
    String name1 = "CAReference00001";
    String name2 = "CAReference00002";
    CVCAFile f = new CVCAFile(name1, name2);
    assertEquals(name1, f.getCAReference().getName());
    assertEquals(name2, f.getAltCAReference().getName());
  }

  public void testReflexive1() {
    try {
      String name1 = "CAReference00001";
      String name2 = "CAReference00002";
      CVCAFile f = new CVCAFile(name1, name2);
      InputStream in = new ByteArrayInputStream(f.getEncoded());
      CVCAFile f2 = new CVCAFile(in);
      assertTrue(Arrays.equals(f.getEncoded(), f2.getEncoded()));
    } catch (Exception e) {
      fail(e.getMessage());
    }
  }

  public void testReflexive2() {
    try {
      String name1 = "CAReference00001";
      CVCAFile f = new CVCAFile(name1, null);
      InputStream in = new ByteArrayInputStream(f.getEncoded());
      CVCAFile f2 = new CVCAFile(in);
      assertTrue(Arrays.equals(f.getEncoded(), f2.getEncoded()));
    } catch (Exception e) {
      fail(e.getMessage());
    }
  }
}
