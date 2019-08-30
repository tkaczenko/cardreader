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
 * $Id: CVCAuthorizationTemplateTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.cert;

import org.jmrtd.cert.CVCAuthorizationTemplate;
import org.jmrtd.cert.CVCAuthorizationTemplate.Permission;
import org.jmrtd.cert.CVCAuthorizationTemplate.Role;

import junit.framework.TestCase;

public class CVCAuthorizationTemplateTest extends TestCase {

  public void testCVCAuthorizationTemplate() {
    for (Role role: Role.values()) {
      for (Permission permission: Permission.values()) {
        testCVCAuthorizationTemplate(role, permission);
      }
    }
  }

  public void testCVCAuthorizationTemplate(Role role, Permission accessRight) {
    CVCAuthorizationTemplate template = new CVCAuthorizationTemplate(role, accessRight);
    assertEquals(role, template.getRole());
    assertEquals(accessRight, template.getAccessRight());
  }

//  public void testPermissionMinimal() {
//    for (Permission permission: Permission.values()) {
//      assertTrue("Failed for " + permission, Permission.READ_ACCESS_DG3_AND_DG4.implies(permission));
//    }
//  }

  public void testPermissionImplicationReflexive() {
    for (Permission permission: Permission.values()) {
      assertTrue(permission.implies(permission));
    }
  }

//  public void testPermissionImplicationTotal() {
//    for (Permission permission1: Permission.values()) {
//      for (Permission permission2: Permission.values()) {
//        assertTrue(permission1.implies(permission1) || permission2.implies(permission1));
//      }
//    }
//  }
}
