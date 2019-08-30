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
 * $Id: LDSFileUtilTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.lds;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.PassportService;
import org.jmrtd.lds.LDSFile;
import org.jmrtd.lds.LDSFileUtil;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.icao.COMFile;
import org.jmrtd.lds.icao.DG14File;
import org.jmrtd.lds.icao.DG15File;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.icao.DG3File;
import org.jmrtd.lds.icao.DG4File;

import junit.framework.TestCase;

/**
 * Tests some of the functionality provided by the {@code LDSFileUtil} class.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1813 $
 */
public class LDSFileUtilTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd.test.lds");

  public void testGetLDSFile() {

    try {
      COMFile comFile = COMFileTest.createTestObject();
      testGetLDSFile(PassportService.EF_COM, comFile.getEncoded(), comFile);

      DG1File dg1File = DG1FileTest.createTestObject();
      testGetLDSFile(PassportService.EF_DG1, dg1File.getEncoded(), dg1File);

      DG2File dg2File = DG2FileTest.createTestObject();
      testGetLDSFile(PassportService.EF_DG2, dg2File.getEncoded(), dg2File);

      DG3File dg3File = DG3FileTest.createTestObject();
      //    testGetLDSFile(PassportService.EF_DG3, dg3File.getEncoded(), dg3File); // FIXME

      DG4File dg4File = DG4FileTest.createTestObject();
      //      testGetLDSFile(PassportService.EF_DG4, dg4File.getEncoded(), dg4File); // FIXME

      DG14File dg14File = new DG14File(new ByteArrayInputStream(DG14FileTest.getSpecSampleDG14File()));
      testGetLDSFile(PassportService.EF_DG14, dg14File.getEncoded(), dg14File);

      DG15File dg15File = DG15FileTest.createTestObject();
      testGetLDSFile(PassportService.EF_DG15, dg15File.getEncoded(), dg15File);

      SODFile sodFile = SODFileTest.createTestObject("SHA-256", "SHA256WithRSA");
      testGetLDSFile(PassportService.EF_SOD, sodFile.getEncoded(), sodFile);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }

  public void testGetLDSFile(short fid, byte[] bytes, LDSFile expectedFile) {
    try {
      LDSFile actualFile = LDSFileUtil.getLDSFile(fid, new ByteArrayInputStream(bytes));
      assertEquals(expectedFile, actualFile);
    } catch (Exception ioe) {
      LOGGER.log(Level.WARNING, "Unexpected exception", ioe);
      fail(ioe.getMessage());
    }
  }

  public void testCompatibilityDataGroups() {
    for (int dgNumber = 1; dgNumber <= 16; dgNumber++) {
      testCompatibilityDataGroups(dgNumber);
    }
  }

  public void testCompatibilityDataGroups(int dgNumber) {
    int tag = LDSFileUtil.lookupTagByDataGroupNumber(dgNumber);
    int otherDGNumber = LDSFileUtil.lookupDataGroupNumberByTag(tag);
    assertEquals(dgNumber, otherDGNumber);

    int otherTag = LDSFileUtil.lookupTagByDataGroupNumber(dgNumber);
    assertEquals(tag, otherTag);

    short fidByDGNumber = LDSFileUtil.lookupFIDByDataGroupNumber(dgNumber);
    short fidByTag = LDSFileUtil.lookupFIDByTag(tag);
    assertEquals(fidByDGNumber, fidByTag);

    int tagByFID = LDSFileUtil.lookupTagByFID(fidByDGNumber);
    assertEquals(tag, tagByFID);

    int dgNumberByFID = LDSFileUtil.lookupDataGroupNumberByFID(fidByDGNumber);
    assertEquals(dgNumber, dgNumberByFID);

    int sfi = LDSFileUtil.lookupSFIByFID(fidByDGNumber);
    int fidBySFI = LDSFileUtil.lookupFIDBySFI((byte)sfi);
    assertEquals(fidByDGNumber, fidBySFI);

    String fileNameByTag = LDSFileUtil.lookupFileNameByTag(tag);
    String fileNameByFID = LDSFileUtil.lookupFileNameByFID(fidByDGNumber);
    assertEquals(fileNameByTag, fileNameByFID);
  }

  public void testDGNumbers() {
    COMFile comFile = COMFileTest.createTestObject();
    List<Integer> dgNumbersFromCOM = LDSFileUtil.getDataGroupNumbers(comFile);
    assertEquals(Arrays.asList(new Integer[] { 1, 2, 15 }), dgNumbersFromCOM);

    SODFile sodFile = SODFileTest.createTestObject("SHA-256", "SHA256WithRSA");
    List<Integer> dgNumbersFromSOd = LDSFileUtil.getDataGroupNumbers(sodFile);
    assertEquals(Arrays.asList(new Integer[] { 1, 2 }), dgNumbersFromSOd);
  }
}
