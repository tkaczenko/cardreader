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
 * $Id: LDSFileUtil.java 1781 2018-05-25 11:41:48Z martijno $
 */

package org.jmrtd.lds;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.PassportService;
import org.jmrtd.lds.icao.COMFile;
import org.jmrtd.lds.icao.DG11File;
import org.jmrtd.lds.icao.DG12File;
import org.jmrtd.lds.icao.DG14File;
import org.jmrtd.lds.icao.DG15File;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.icao.DG3File;
import org.jmrtd.lds.icao.DG4File;
import org.jmrtd.lds.icao.DG5File;
import org.jmrtd.lds.icao.DG6File;
import org.jmrtd.lds.icao.DG7File;

/**
 * Static LDS file methods.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1781 $
 */
public final class LDSFileUtil {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public static final Map<Short, Byte> FID_TO_SFI = createFIDToSFIMap();

  /**
   * Objects of this class should not be constructed.
   */
  private LDSFileUtil() {
  }

  /**
   * Factory method for creating LDS files for a given input stream.
   *
   * @param fid file identifier
   * @param inputStream a given input stream
   *
   * @return a specific file
   *
   * @throws IOException on reading error from the input stream
   */
  public static AbstractLDSFile getLDSFile(short fid, InputStream inputStream) throws IOException {
    switch (fid) {
      case PassportService.EF_COM:
        return new COMFile(inputStream);
      case PassportService.EF_DG1:
        return new DG1File(inputStream);
      case PassportService.EF_DG2:
        return new DG2File(inputStream);
      case PassportService.EF_DG3:
        return new DG3File(inputStream);
      case PassportService.EF_DG4:
        return new DG4File(inputStream);
      case PassportService.EF_DG5:
        return new DG5File(inputStream);
      case PassportService.EF_DG6:
        return new DG6File(inputStream);
      case PassportService.EF_DG7:
        return new DG7File(inputStream);
      case PassportService.EF_DG8:
        throw new IllegalArgumentException("DG8 files are not yet supported");
      case PassportService.EF_DG9:
        throw new IllegalArgumentException("DG9 files are not yet supported");
      case PassportService.EF_DG10:
        throw new IllegalArgumentException("DG10 files are not yet supported");
      case PassportService.EF_DG11:
        return new DG11File(inputStream);
      case PassportService.EF_DG12:
        return new DG12File(inputStream);
      case PassportService.EF_DG13:
        throw new IllegalArgumentException("DG13 files are not yet supported");
      case PassportService.EF_DG14:
        return new DG14File(inputStream);
      case PassportService.EF_DG15:
        return new DG15File(inputStream);
      case PassportService.EF_DG16:
        throw new IllegalArgumentException("DG16 files are not yet supported");
      case PassportService.EF_SOD:
        return new SODFile(inputStream);
      case PassportService.EF_CVCA:
        return new CVCAFile(inputStream);
      default:
        BufferedInputStream bufferedIn = new BufferedInputStream(inputStream, 37);
        try {
          bufferedIn.mark(37);
          /* Just try, will read 36 bytes at most, and we can reset bufferedIn. */
          return new CVCAFile(fid, bufferedIn);
        } catch (Exception e) {
          LOGGER.log(Level.WARNING, "Unknown file " + Integer.toHexString(fid), e);
          bufferedIn.reset();
          throw new NumberFormatException("Unknown file " + Integer.toHexString(fid));
        }
    }
  }

  /**
   * Finds a file identifier for an ICAO tag.
   *
   * Corresponds to Table A1 in ICAO-TR-LDS_1.7_2004-05-18.
   *
   * @param tag an ICAO tag (the first byte of the EF)
   *
   * @return a file identifier.
   */
  public static short lookupFIDByTag(int tag) {
    switch(tag) {
      case LDSFile.EF_COM_TAG:
        return PassportService.EF_COM;
      case LDSFile.EF_DG1_TAG:
        return PassportService.EF_DG1;
      case LDSFile.EF_DG2_TAG:
        return PassportService.EF_DG2;
      case LDSFile.EF_DG3_TAG:
        return PassportService.EF_DG3;
      case LDSFile.EF_DG4_TAG:
        return PassportService.EF_DG4;
      case LDSFile.EF_DG5_TAG:
        return PassportService.EF_DG5;
      case LDSFile.EF_DG6_TAG:
        return PassportService.EF_DG6;
      case LDSFile.EF_DG7_TAG:
        return PassportService.EF_DG7;
      case LDSFile.EF_DG8_TAG:
        return PassportService.EF_DG8;
      case LDSFile.EF_DG9_TAG:
        return PassportService.EF_DG9;
      case LDSFile.EF_DG10_TAG:
        return PassportService.EF_DG10;
      case LDSFile.EF_DG11_TAG:
        return PassportService.EF_DG11;
      case LDSFile.EF_DG12_TAG:
        return PassportService.EF_DG12;
      case LDSFile.EF_DG13_TAG:
        return PassportService.EF_DG13;
      case LDSFile.EF_DG14_TAG:
        return PassportService.EF_DG14;
      case LDSFile.EF_DG15_TAG:
        return PassportService.EF_DG15;
      case LDSFile.EF_DG16_TAG:
        return PassportService.EF_DG16;
      case LDSFile.EF_SOD_TAG:
        return PassportService.EF_SOD;
      default:
        throw new NumberFormatException("Unknown tag " + Integer.toHexString(tag));
    }
  }

  /**
   * Finds a data group number for an ICAO tag.
   *
   * @param tag an ICAO tag (the first byte of the EF)
   *
   * @return a data group number (1-16)
   */
  public static int lookupDataGroupNumberByTag(int tag) {
    switch (tag) {
      case LDSFile.EF_DG1_TAG:
        return 1;
      case LDSFile.EF_DG2_TAG:
        return 2;
      case LDSFile.EF_DG3_TAG:
        return 3;
      case LDSFile.EF_DG4_TAG:
        return 4;
      case LDSFile.EF_DG5_TAG:
        return 5;
      case LDSFile.EF_DG6_TAG:
        return 6;
      case LDSFile.EF_DG7_TAG:
        return 7;
      case LDSFile.EF_DG8_TAG:
        return 8;
      case LDSFile.EF_DG9_TAG:
        return 9;
      case LDSFile.EF_DG10_TAG:
        return 10;
      case LDSFile.EF_DG11_TAG:
        return 11;
      case LDSFile.EF_DG12_TAG:
        return 12;
      case LDSFile.EF_DG13_TAG:
        return 13;
      case LDSFile.EF_DG14_TAG:
        return 14;
      case LDSFile.EF_DG15_TAG:
        return 15;
      case LDSFile.EF_DG16_TAG:
        return 16;
      default:
        throw new NumberFormatException("Unknown tag " + Integer.toHexString(tag));
    }
  }

  /**
   * Finds an ICAO tag for a data group number.
   *
   *
   * @param number a data group number (1-16)
   *
   * @return an ICAO tag (the first byte of the EF)
   */
  public static int lookupTagByDataGroupNumber(int number) {
    switch (number) {
      case 1:
        return LDSFile.EF_DG1_TAG;
      case 2:
        return LDSFile.EF_DG2_TAG;
      case 3:
        return LDSFile.EF_DG3_TAG;
      case 4:
        return LDSFile.EF_DG4_TAG;
      case 5:
        return LDSFile.EF_DG5_TAG;
      case 6:
        return LDSFile.EF_DG6_TAG;
      case 7:
        return LDSFile.EF_DG7_TAG;
      case 8:
        return LDSFile.EF_DG8_TAG;
      case 9:
        return LDSFile.EF_DG9_TAG;
      case 10:
        return LDSFile.EF_DG10_TAG;
      case 11:
        return LDSFile.EF_DG11_TAG;
      case 12:
        return LDSFile.EF_DG12_TAG;
      case 13:
        return LDSFile.EF_DG13_TAG;
      case 14:
        return LDSFile.EF_DG14_TAG;
      case 15:
        return LDSFile.EF_DG15_TAG;
      case 16:
        return LDSFile.EF_DG16_TAG;
      default:
        throw new NumberFormatException("Unknown number " + number);
    }
  }

  /**
   * Finds an ICAO tag for a data group number.
   *
   *
   * @param number a data group number (1-16)
   *
   * @return a file identifier
   */
  public static short lookupFIDByDataGroupNumber(int number) {
    switch (number) {
      case 1:
        return PassportService.EF_DG1;
      case 2:
        return PassportService.EF_DG2;
      case 3:
        return PassportService.EF_DG3;
      case 4:
        return PassportService.EF_DG4;
      case 5:
        return PassportService.EF_DG5;
      case 6:
        return PassportService.EF_DG6;
      case 7:
        return PassportService.EF_DG7;
      case 8:
        return PassportService.EF_DG8;
      case 9:
        return PassportService.EF_DG9;
      case 10:
        return PassportService.EF_DG10;
      case 11:
        return PassportService.EF_DG11;
      case 12:
        return PassportService.EF_DG12;
      case 13:
        return PassportService.EF_DG13;
      case 14:
        return PassportService.EF_DG14;
      case 15:
        return PassportService.EF_DG15;
      case 16:
        return PassportService.EF_DG16;
      default:
        throw new NumberFormatException("Unknown number " + number);
    }
  }

  /**
   * Finds an ICAO tag for a file identifier.
   *
   * Corresponds to Table A1 in ICAO-TR-LDS_1.7_2004-05-18.
   *
   * @param fid a file identifier
   *
   * @return a an ICAO tag (first byte of EF)
   */
  public static short lookupTagByFID(short fid) {
    switch(fid) {
      case PassportService.EF_COM:
        return LDSFile.EF_COM_TAG;
      case PassportService.EF_DG1:
        return LDSFile.EF_DG1_TAG;
      case PassportService.EF_DG2:
        return LDSFile.EF_DG2_TAG;
      case PassportService.EF_DG3:
        return LDSFile.EF_DG3_TAG;
      case PassportService.EF_DG4:
        return LDSFile.EF_DG4_TAG;
      case PassportService.EF_DG5:
        return LDSFile.EF_DG5_TAG;
      case PassportService.EF_DG6:
        return LDSFile.EF_DG6_TAG;
      case PassportService.EF_DG7:
        return LDSFile.EF_DG7_TAG;
      case PassportService.EF_DG8:
        return LDSFile.EF_DG8_TAG;
      case PassportService.EF_DG9:
        return LDSFile.EF_DG9_TAG;
      case PassportService.EF_DG10:
        return LDSFile.EF_DG10_TAG;
      case PassportService.EF_DG11:
        return LDSFile.EF_DG11_TAG;
      case PassportService.EF_DG12:
        return LDSFile.EF_DG12_TAG;
      case PassportService.EF_DG13:
        return LDSFile.EF_DG13_TAG;
      case PassportService.EF_DG14:
        return LDSFile.EF_DG14_TAG;
      case PassportService.EF_DG15:
        return LDSFile.EF_DG15_TAG;
      case PassportService.EF_DG16:
        return LDSFile.EF_DG16_TAG;
      case PassportService.EF_SOD:
        return LDSFile.EF_SOD_TAG;
      default:
        throw new NumberFormatException("Unknown fid " + Integer.toHexString(fid));
    }
  }

  /**
   * Finds a data group number by file identifier.
   *
   * @param fid a file id
   *
   * @return a data group number
   */
  public static int lookupDataGroupNumberByFID(short fid) {
    switch(fid) {
      case PassportService.EF_DG1:
        return 1;
      case PassportService.EF_DG2:
        return 2;
      case PassportService.EF_DG3:
        return 3;
      case PassportService.EF_DG4:
        return 4;
      case PassportService.EF_DG5:
        return 5;
      case PassportService.EF_DG6:
        return 6;
      case PassportService.EF_DG7:
        return 7;
      case PassportService.EF_DG8:
        return 8;
      case PassportService.EF_DG9:
        return 9;
      case PassportService.EF_DG10:
        return 10;
      case PassportService.EF_DG11:
        return 11;
      case PassportService.EF_DG12:
        return 12;
      case PassportService.EF_DG13:
        return 13;
      case PassportService.EF_DG14:
        return 14;
      case PassportService.EF_DG15:
        return 15;
      case PassportService.EF_DG16:
        return 16;
      default:
        throw new NumberFormatException("Unknown fid " + Integer.toHexString(fid));
    }
  }

  /**
   * Returns a mnemonic name corresponding to the file represented by the
   * given ICAO tag, such as "EF_COM", "EF_SOD", or "EF_DG1".
   *
   * @param tag an ICAO tag (the first byte of the EF)
   *
   * @return a mnemonic name corresponding to the file represented by the given ICAO tag
   */
  public static String lookupFileNameByTag(int tag) {
    switch (tag) {
      case LDSFile.EF_COM_TAG:
        return "EF_COM";
      case LDSFile.EF_DG1_TAG:
        return "EF_DG1";
      case LDSFile.EF_DG2_TAG:
        return "EF_DG2";
      case LDSFile.EF_DG3_TAG:
        return "EF_DG3";
      case LDSFile.EF_DG4_TAG:
        return "EF_DG4";
      case LDSFile.EF_DG5_TAG:
        return "EF_DG5";
      case LDSFile.EF_DG6_TAG:
        return "EF_DG6";
      case LDSFile.EF_DG7_TAG:
        return "EF_DG7";
      case LDSFile.EF_DG8_TAG:
        return "EF_DG8";
      case LDSFile.EF_DG9_TAG:
        return "EF_DG9";
      case LDSFile.EF_DG10_TAG:
        return "EF_DG10";
      case LDSFile.EF_DG11_TAG:
        return "EF_DG11";
      case LDSFile.EF_DG12_TAG:
        return "EF_DG12";
      case LDSFile.EF_DG13_TAG:
        return "EF_DG13";
      case LDSFile.EF_DG14_TAG:
        return "EF_DG14";
      case LDSFile.EF_DG15_TAG:
        return "EF_DG15";
      case LDSFile.EF_DG16_TAG:
        return "EF_DG16";
      case LDSFile.EF_SOD_TAG:
        return "EF_SOD";
      default: return "File with tag 0x" + Integer.toHexString(tag);
    }
  }

  /**
   * Returns a mnemonic name corresponding to the file represented by the
   * given file identifier, such as "EF_COM", "EF_SOD", or "EF_DG1".
   *
   * @param fid an LDS file identifiers
   *
   * @return a mnemonic name corresponding to the file represented by the given ICAO tag
   */
  public static String lookupFileNameByFID(int fid) {
    switch (fid) {
      case PassportService.EF_COM:
        return "EF_COM";
      case PassportService.EF_DG1:
        return "EF_DG1";
      case PassportService.EF_DG2:
        return "EF_DG2";
      case PassportService.EF_DG3:
        return "EF_DG3";
      case PassportService.EF_DG4:
        return "EF_DG4";
      case PassportService.EF_DG5:
        return "EF_DG5";
      case PassportService.EF_DG6:
        return "EF_DG6";
      case PassportService.EF_DG7:
        return "EF_DG7";
      case PassportService.EF_DG8:
        return "EF_DG8";
      case PassportService.EF_DG9:
        return "EF_DG9";
      case PassportService.EF_DG10:
        return "EF_DG10";
      case PassportService.EF_DG11:
        return "EF_DG11";
      case PassportService.EF_DG12:
        return "EF_DG12";
      case PassportService.EF_DG13:
        return "EF_DG13";
      case PassportService.EF_DG14:
        return "EF_DG14";
      case PassportService.EF_DG15:
        return "EF_DG15";
      case PassportService.EF_DG16:
        return "EF_DG16";
      case PassportService.EF_SOD:
        return "EF_SOD";
      default:
        return "File with FID 0x" + Integer.toHexString(fid);
    }
  }

  /**
   * Returns the short (one  byte) file identifier corresponding
   * to the given (two byte) file identifier.
   *
   * @param fid a file identifier
   *
   * @return the corresponding short file identifier
   */
  public static int lookupSFIByFID(short fid) {
    Byte sfiByte = FID_TO_SFI.get(fid);
    if (sfiByte == null) {
      throw new NumberFormatException("Unknown FID " + Integer.toHexString(fid));
    }

    return sfiByte & 0xFF;
  }

  /**
   * Looks up a file identifier for a given short file identifier.
   *
   * @param sfi the short file identifier
   *
   * @return a file identifier
   */
  public static short lookupFIDBySFI(byte sfi) {
    switch (sfi) {
      case PassportService.SFI_COM:
        return PassportService.EF_COM;
      case PassportService.SFI_DG1:
        return PassportService.EF_DG1;
      case PassportService.SFI_DG2:
        return PassportService.EF_DG2;
      case PassportService.SFI_DG3:
        return PassportService.EF_DG3;
      case PassportService.SFI_DG4:
        return PassportService.EF_DG4;
      case PassportService.SFI_DG5:
        return PassportService.EF_DG5;
      case PassportService.SFI_DG6:
        return PassportService.EF_DG6;
      case PassportService.SFI_DG7:
        return PassportService.EF_DG7;
      case PassportService.SFI_DG8:
        return PassportService.EF_DG8;
      case PassportService.SFI_DG9:
        return PassportService.EF_DG9;
      case PassportService.SFI_DG10:
        return PassportService.EF_DG10;
      case PassportService.SFI_DG11:
        return PassportService.EF_DG11;
      case PassportService.SFI_DG12:
        return PassportService.EF_DG12;
      case PassportService.SFI_DG13:
        return PassportService.EF_DG13;
      case PassportService.SFI_DG14:
        return PassportService.EF_DG14;
      case PassportService.SFI_DG15:
        return PassportService.EF_DG15;
      case PassportService.SFI_DG16:
        return PassportService.EF_DG16;
      case PassportService.SFI_SOD:
        return PassportService.EF_SOD;
      case PassportService.SFI_CVCA:
        return PassportService.EF_CVCA;
      default:
        throw new NumberFormatException("Unknown SFI " + Integer.toHexString(sfi));
    }
  }

  /**
   * Returns the data group list from the security object (SOd).
   *
   * @param sodFile the security object
   *
   * @return the list of data group numbers
   */
  public static List<Integer> getDataGroupNumbers(SODFile sodFile) {
    /* Get the list of DGs from EF.SOd, we don't trust EF.COM. */
    List<Integer> dgNumbers = new ArrayList<Integer>();
    if (sodFile == null) {
      return dgNumbers;
    }

    dgNumbers.addAll(sodFile.getDataGroupHashes().keySet());
    Collections.sort(dgNumbers); /* NOTE: need to sort it, since we get keys as a set. */
    return dgNumbers;
  }

  /**
   * Returns the data group list from the document index file (COM).
   *
   * @param comFile the document index file
   *
   * @return the list with data group number according to the document index file
   */
  public static List<Integer> getDataGroupNumbers(COMFile comFile) {
    List<Integer> dgNumbers = new ArrayList<Integer>();
    if (comFile == null) {
      return dgNumbers;
    }

    int[] tagList = comFile.getTagList();
    dgNumbers.addAll(toDataGroupList(tagList));
    Collections.sort(dgNumbers); // NOTE: sort it, just in case.
    return dgNumbers;
  }

  /**
   * Converts a list with ICAO tags into a list of ICAO data group numbers.
   *
   * @param tagList a list of tags specified in ICAO Doc 9303
   *
   * @return the list with data group number according to the security object
   */
  private static List<Integer> toDataGroupList(int[] tagList) {
    if (tagList == null) {
      return Collections.emptyList();
    }
    List<Integer> dgNumberList = new ArrayList<Integer>(tagList.length);
    for (int tag: tagList) {
      try {
        int dgNumber = LDSFileUtil.lookupDataGroupNumberByTag(tag);
        dgNumberList.add(dgNumber);
      } catch (NumberFormatException nfe) {
        LOGGER.log(Level.WARNING, "Could not find DG number for tag: " + Integer.toHexString(tag), nfe);
      }
    }
    return dgNumberList;
  }

  /**
   * Creates a map for looking up short file identifiers based on file identifiers.
   *
   * @return the lookup map
   */
  private static Map<Short, Byte> createFIDToSFIMap() {
    Map<Short, Byte> fidToSFI = new HashMap<Short, Byte>(20);
    fidToSFI.put(PassportService.EF_COM, PassportService.SFI_COM);
    fidToSFI.put(PassportService.EF_DG1, PassportService.SFI_DG1);
    fidToSFI.put(PassportService.EF_DG2, PassportService.SFI_DG2);
    fidToSFI.put(PassportService.EF_DG3, PassportService.SFI_DG3);
    fidToSFI.put(PassportService.EF_DG4, PassportService.SFI_DG4);
    fidToSFI.put(PassportService.EF_DG5, PassportService.SFI_DG5);
    fidToSFI.put(PassportService.EF_DG6, PassportService.SFI_DG6);
    fidToSFI.put(PassportService.EF_DG7, PassportService.SFI_DG7);
    fidToSFI.put(PassportService.EF_DG8, PassportService.SFI_DG8);
    fidToSFI.put(PassportService.EF_DG9,  PassportService.SFI_DG9);
    fidToSFI.put(PassportService.EF_DG10, PassportService.SFI_DG10);
    fidToSFI.put(PassportService.EF_DG11, PassportService.SFI_DG11);
    fidToSFI.put(PassportService.EF_DG12, PassportService.SFI_DG12);
    fidToSFI.put(PassportService.EF_DG13, PassportService.SFI_DG13);
    fidToSFI.put(PassportService.EF_DG14, PassportService.SFI_DG14);
    fidToSFI.put(PassportService.EF_DG15, PassportService.SFI_DG15);
    fidToSFI.put(PassportService.EF_DG16, PassportService.SFI_DG16);
    fidToSFI.put(PassportService.EF_SOD, PassportService.SFI_SOD);
    fidToSFI.put(PassportService.EF_CVCA, PassportService.SFI_CVCA);
    return Collections.unmodifiableMap(fidToSFI);
  }
}
