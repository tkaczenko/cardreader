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
 * $Id: TerminalAuthenticationInfoTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.lds;

import org.jmrtd.lds.TerminalAuthenticationInfo;

import junit.framework.TestCase;

/**
 * Tests for the TerminalAuthenticationInfo data type.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1813 $
 *
 * @since 0.6.2
 */
public class TerminalAuthenticationInfoTest extends TestCase {

  public void testTerminalAuthenticationInfo() {
    TerminalAuthenticationInfo taInfo = new TerminalAuthenticationInfo();
    assertEquals(TerminalAuthenticationInfo.ID_TA, taInfo.getObjectIdentifier()); // 0.4.0.127.0.7.2.2.2
    assertEquals("id-TA", taInfo.getProtocolOIDString());
    assertEquals(1, taInfo.getVersion());
    assertEquals(-1, taInfo.getFileId());
    assertEquals(-1, taInfo.getShortFileId());
  }
}
