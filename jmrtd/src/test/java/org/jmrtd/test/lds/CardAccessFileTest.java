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
 * $Id: CardAccessFileTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.lds;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import org.jmrtd.lds.ActiveAuthenticationInfo;
import org.jmrtd.lds.CardAccessFile;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.SecurityInfo;

import junit.framework.TestCase;

public class CardAccessFileTest extends TestCase {

  public void testCardAccessFile() {
    ActiveAuthenticationInfo aaInfo = new ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID);
    PACEInfo paceInfo = new PACEInfo(PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, 2, PACEInfo.PARAM_ID_ECP_NIST_P256_R1);
    List<SecurityInfo> securityInfos = Arrays.asList(new SecurityInfo[] { aaInfo, paceInfo });
    CardAccessFile cardAccessFile = new CardAccessFile(securityInfos);

    Collection<SecurityInfo> actualSecurityInfos = cardAccessFile.getSecurityInfos();
    assertEquals(new HashSet<SecurityInfo>(securityInfos), new HashSet<SecurityInfo>(actualSecurityInfos));
  }

  public void testCardAccessFileEquals() {
    ActiveAuthenticationInfo aaInfo = new ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID);
    PACEInfo paceInfo = new PACEInfo(PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, 2, PACEInfo.PARAM_ID_ECP_NIST_P256_R1);
    List<SecurityInfo> securityInfos = Arrays.asList(new SecurityInfo[] { aaInfo, paceInfo });
    CardAccessFile cardAccessFile = new CardAccessFile(securityInfos);

    ActiveAuthenticationInfo anotherAAInfo = new ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID);
    PACEInfo anotherPACEInfo = new PACEInfo(PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, 2, PACEInfo.PARAM_ID_ECP_NIST_P256_R1);
    List<SecurityInfo> anotherSecurityInfos = Arrays.asList(new SecurityInfo[] { anotherAAInfo, anotherPACEInfo });

    CardAccessFile anotherCardAccessFile = new CardAccessFile(anotherSecurityInfos);

    assertEquals(cardAccessFile, anotherCardAccessFile);
  }
}
