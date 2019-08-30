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
 * $Id: BACKeyTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test;

import java.text.SimpleDateFormat;

import org.jmrtd.BACKey;

import junit.framework.TestCase;

public class BACKeyTest extends TestCase {

  public void testBACKey() {
    String documentNumber = "123456789";
    String dateOfBirthString = "710121";
    String dateOfExpiryString = "310309";
    BACKey bacKey = new BACKey(documentNumber, dateOfBirthString, dateOfExpiryString);

    assertEquals("BAC", bacKey.getAlgorithm());
    assertEquals(documentNumber, bacKey.getDocumentNumber());
    assertEquals(dateOfBirthString, bacKey.getDateOfBirth());
    assertEquals(dateOfExpiryString, bacKey.getDateOfExpiry());
  }

  public void testBACKeyNoNull() {
    String documentNumber = "123456789";
    String dateOfBirthString = "710121";
    String dateOfExpiryString = "310309";
    try {
      /* BACKey bacKeyWithNullDocumentNumber = */ new BACKey(null, dateOfBirthString, dateOfExpiryString);
      fail("Cannot use null for document number");
    } catch (Exception expected) {
      // Fine
    }

    try {
      /* BACKey bacKeyWithNullDateOfBirth = */ new BACKey(documentNumber, null, dateOfExpiryString);
      fail("Cannot use null for date of birth");
    } catch (Exception expected) {
      // Fine
    }

    try {
      /* BACKey bacKeyWithNullDateOfExpiry = */ new BACKey(documentNumber, dateOfBirthString, null);
      fail("Cannot use null for date of expiry");
    } catch (Exception expected) {
      // Fine
    }
  }

  public void testBACKeyEquals() {
    String documentNumber = "123456789";
    String dateOfBirthString = "710121";
    String dateOfExpiryString = "310309";

    BACKey bacKey = new BACKey(documentNumber, dateOfBirthString, dateOfExpiryString);
    BACKey anotherBACKey = new BACKey(documentNumber, dateOfBirthString, dateOfExpiryString);

    assertEquals(bacKey.hashCode(), anotherBACKey.hashCode());
    assertEquals(bacKey, anotherBACKey);
    assertEquals(bacKey.toString(), anotherBACKey.toString());
  }

  public void testBACKeyDates() {
    try {
      SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");
      BACKey bacKey = new BACKey("123456789", simpleDateFormat.parse("1971-01-21"), simpleDateFormat.parse("2031-3-9"));

      assertEquals("710121", bacKey.getDateOfBirth());
      assertEquals("310309", bacKey.getDateOfExpiry());
    } catch (Exception e) {
      fail(e.getMessage());
    }
  }

  public void testBACKeyShortDocumentNumber() {
    String dateOfBirthString = "710121";
    String dateOfExpiryString = "310309";

    assertEquals("123456789", (new BACKey("123456789", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("12345678<", (new BACKey("12345678", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("1234567<<", (new BACKey("1234567", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("123456<<<", (new BACKey("123456", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("12345<<<<", (new BACKey("12345", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("1234<<<<<", (new BACKey("1234", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("123<<<<<<", (new BACKey("123", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("12<<<<<<<", (new BACKey("12", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("1<<<<<<<<", (new BACKey("1", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("<<<<<<<<<", (new BACKey("", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());

    assertEquals("123456789", (new BACKey("123456789", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("12345678<", (new BACKey("12345678<", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("1234567<<", (new BACKey("1234567<<", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("123456<<<", (new BACKey("123456<<<", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("12345<<<<", (new BACKey("12345<<<<", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("1234<<<<<", (new BACKey("1234<<<<<", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("123<<<<<<", (new BACKey("123<<<<<<", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("12<<<<<<<", (new BACKey("12<<<<<<<", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("1<<<<<<<<", (new BACKey("1<<<<<<<<", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
    assertEquals("<<<<<<<<<", (new BACKey("<<<<<<<<<", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
  }

  public void testBACKeyLongDocumentNumber() {
    String dateOfBirthString = "710121";
    String dateOfExpiryString = "310309";

    assertEquals("1234567890", (new BACKey("1234567890", dateOfBirthString, dateOfExpiryString)).getDocumentNumber());
  }
}
