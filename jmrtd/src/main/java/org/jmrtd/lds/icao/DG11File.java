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
 * $Id: DG11File.java 1802 2018-11-06 16:29:28Z martijno $
 */

package org.jmrtd.lds.icao;

import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.lds.DataGroup;

import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVOutputStream;
import net.sf.scuba.tlv.TLVUtil;
import net.sf.scuba.util.Hex;

/**
 * File structure for the EF_DG11 file.
 * Datagroup 11 contains additional personal detail(s).
 *
 * All fields are optional. See Section 16 of LDS-TR.
 * <ol>
 * <li>Name of Holder (Primary and Secondary Identifiers, in full)</li>
 * <li>Other Name(s)</li>
 * <li>Personal Number</li>
 * <li>Place of Birth</li>
 * <li>Date of Birth (in full)</li>
 * <li>Address</li>
 * <li>Telephone Number(s)</li>
 * <li>Profession</li>
 * <li>Title</li>
 * <li>Personal Summary</li>
 * <li>Proof of Citizenship [see 14.5.1]</li>
 * <li>Number of Other Valid Travel Documents</li>
 * <li>Other Travel Document Numbers</li>
 * <li>Custody Information</li>
 * </ol>
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1802 $
 */
public class DG11File extends DataGroup {

  private static final long serialVersionUID = 8566312538928662937L;

  public static final int TAG_LIST_TAG = 0x5C;

  public static final int FULL_NAME_TAG = 0x5F0E;
  public static final int OTHER_NAME_TAG = 0x5F0F;
  public static final int PERSONAL_NUMBER_TAG = 0x5F10;
  public static final int FULL_DATE_OF_BIRTH_TAG = 0x5F2B; // In 'CCYYMMDD' format.
  public static final int PLACE_OF_BIRTH_TAG = 0x5F11; // Fields separated by '<'
  public static final int PERMANENT_ADDRESS_TAG = 0x5F42; // Fields separated by '<'
  public static final int TELEPHONE_TAG = 0x5F12;
  public static final int PROFESSION_TAG = 0x5F13;
  public static final int TITLE_TAG = 0x5F14;
  public static final int PERSONAL_SUMMARY_TAG = 0x5F15;
  public static final int PROOF_OF_CITIZENSHIP_TAG = 0x5F16; // Compressed image per ISO/IEC 10918
  public static final int OTHER_VALID_TD_NUMBERS_TAG = 0x5F17; // Separated by '<'
  public static final int CUSTODY_INFORMATION_TAG = 0x5F18;

  public static final int CONTENT_SPECIFIC_CONSTRUCTED_TAG = 0xA0; // 5F0F is always used inside A0 constructed object
  public static final int COUNT_TAG = 0x02; // Used in A0 constructed object to indicate single byte count of simple objects

  private static final String SDF = "yyyyMMdd";

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private String nameOfHolder;
  private List<String> otherNames;
  private String personalNumber;
  private String fullDateOfBirth;
  private List<String> placeOfBirth;
  private List<String> permanentAddress;
  private String telephone;
  private String profession;
  private String title;
  private String personalSummary;
  private byte[] proofOfCitizenship;
  private List<String> otherValidTDNumbers;
  private String custodyInformation;

  private List<Integer> tagPresenceList;

  /**
   * Constructs a file from binary representation.
   *
   * @param inputStream an input stream
   *
   * @throws IOException if reading fails
   */
  public DG11File(InputStream inputStream) throws IOException {
    super(EF_DG11_TAG, inputStream);
  }

  /**
   * Constructs a new file. Use <code>null</code> if data element is not present.
   * Use <code>&#39;&lt;&#39;</code> as separator.
   *
   * @param nameOfHolder data element
   * @param otherNames data element
   * @param personalNumber data element
   * @param fullDateOfBirth data element
   * @param placeOfBirth data element
   * @param permanentAddress data element
   * @param telephone data element
   * @param profession data element
   * @param title data element
   * @param personalSummary data element
   * @param proofOfCitizenship data element
   * @param otherValidTDNumbers data element
   * @param custodyInformation data element
   */
  public DG11File(String nameOfHolder,
      List<String> otherNames, String personalNumber,
      Date fullDateOfBirth, List<String> placeOfBirth, List<String> permanentAddress,
      String telephone, String profession, String title,
      String personalSummary, byte[] proofOfCitizenship,
      List<String> otherValidTDNumbers, String custodyInformation) {
    this(nameOfHolder,
        otherNames, personalNumber,
        new SimpleDateFormat(SDF).format(fullDateOfBirth), placeOfBirth, permanentAddress,
        telephone, profession, title,
        personalSummary, proofOfCitizenship,
        otherValidTDNumbers, custodyInformation);
  }

  /**
   * Constructs a new file. Use <code>null</code> if data element is not present.
   * Use <code>&#39;&lt;&#39;</code> as separator.
   *
   * @param nameOfHolder data element
   * @param otherNames data element
   * @param personalNumber data element
   * @param fullDateOfBirth data element
   * @param placeOfBirth data element
   * @param permanentAddress data element
   * @param telephone data element
   * @param profession data element
   * @param title data element
   * @param personalSummary data element
   * @param proofOfCitizenship data element
   * @param otherValidTDNumbers data element
   * @param custodyInformation data element
   */
  public DG11File(String nameOfHolder,
      List<String> otherNames, String personalNumber,
      String fullDateOfBirth, List<String> placeOfBirth, List<String> permanentAddress,
      String telephone, String profession, String title,
      String personalSummary, byte[] proofOfCitizenship,
      List<String> otherValidTDNumbers, String custodyInformation) {
    super(EF_DG11_TAG);
    this.nameOfHolder = nameOfHolder;
    this.otherNames = otherNames == null ? new ArrayList<String>() : new ArrayList<String>(otherNames);
    this.personalNumber = personalNumber;
    this.fullDateOfBirth = fullDateOfBirth;
    this.placeOfBirth = placeOfBirth == null ? new ArrayList<String>() : new ArrayList<String>(placeOfBirth);
    this.permanentAddress = permanentAddress;
    this.telephone = telephone;
    this.profession = profession;
    this.title = title;
    this.personalSummary = personalSummary;
    this.proofOfCitizenship = proofOfCitizenship; // FIXME: deep copy
    this.otherValidTDNumbers = otherValidTDNumbers == null ? new ArrayList<String>() : new ArrayList<String>(otherValidTDNumbers);
    this.custodyInformation = custodyInformation;
  }

  /* Accessors below. */

  @Override
  public int getTag() {
    return EF_DG11_TAG;
  }

  /**
   * Returns the list of tags of fields actually present.
   *
   * @return list of tags
   */
  public List<Integer> getTagPresenceList() {
    if (tagPresenceList != null) {
      return tagPresenceList;
    }
    tagPresenceList = new ArrayList<Integer>(12);
    if (nameOfHolder != null) {
      tagPresenceList.add(FULL_NAME_TAG);
    }
    if (otherNames != null && !otherNames.isEmpty()) {
      tagPresenceList.add(OTHER_NAME_TAG);
    }
    if (personalNumber != null) {
      tagPresenceList.add(PERSONAL_NUMBER_TAG);
    }
    if (fullDateOfBirth != null) {
      tagPresenceList.add(FULL_DATE_OF_BIRTH_TAG);
    }
    if (placeOfBirth != null && !placeOfBirth.isEmpty()) {
      tagPresenceList.add(PLACE_OF_BIRTH_TAG);
    }
    if (permanentAddress != null && !permanentAddress.isEmpty()) {
      tagPresenceList.add(PERMANENT_ADDRESS_TAG);
    }
    if (telephone != null) {
      tagPresenceList.add(TELEPHONE_TAG);
    }
    if (profession != null) {
      tagPresenceList.add(PROFESSION_TAG);
    }
    if (title != null) {
      tagPresenceList.add(TITLE_TAG);
    }
    if (personalSummary != null) {
      tagPresenceList.add(PERSONAL_SUMMARY_TAG);
    }
    if (proofOfCitizenship != null) {
      tagPresenceList.add(PROOF_OF_CITIZENSHIP_TAG);
    }
    if (otherValidTDNumbers != null && !otherValidTDNumbers.isEmpty()) {
      tagPresenceList.add(OTHER_VALID_TD_NUMBERS_TAG);
    }
    if (custodyInformation != null) {
      tagPresenceList.add(CUSTODY_INFORMATION_TAG);
    }
    return tagPresenceList;
  }

  /**
   * Returns the full name of the holder (primary and secondary identifiers).
   *
   * @return the name of holder
   */
  public String getNameOfHolder() {
    return nameOfHolder;
  }

  /**
   * Returns the other names.
   *
   * @return the other names, or empty list when not present
   */
  public List<String> getOtherNames() {
    return otherNames == null ? new ArrayList<String>() : new ArrayList<String>(otherNames);
  }

  /**
   * Returns the personal number.
   *
   * @return the personal number
   */
  public String getPersonalNumber() {
    return personalNumber;
  }

  /**
   * Returns the full date of birth.
   *
   * @return the full date of birth
   */
  public String getFullDateOfBirth() {
    return fullDateOfBirth;
  }

  /**
   * Returns the place of birth.
   *
   * @return the place of birth
   */
  public List<String> getPlaceOfBirth() {
    return placeOfBirth;
  }

  /**
   * Returns the permanent address.
   *
   * @return the permanent address
   */
  public List<String> getPermanentAddress() {
    return permanentAddress;
  }

  /**
   * Returns the telephone number.
   *
   * @return the telephone
   */
  public String getTelephone() {
    return telephone;
  }

  /**
   * Returns the holder's profession.
   *
   * @return the profession
   */
  public String getProfession() {
    return profession;
  }

  /**
   * Returns the holder's title.
   *
   * @return the title
   */
  public String getTitle() {
    return title;
  }

  /**
   * Returns the personal summary.
   *
   * @return the personal summary
   */
  public String getPersonalSummary() {
    return personalSummary;
  }

  /**
   * Returns the proof of citizenship.
   *
   * @return the proof of citizenship
   */
  public byte[] getProofOfCitizenship() {
    return proofOfCitizenship;
  }

  /**
   * Returns the other valid travel document numbers.
   *
   * @return the other valid travel document numbers
   */
  public List<String> getOtherValidTDNumbers() {
    return otherValidTDNumbers;
  }

  /**
   * Returns the custody information.
   *
   * @return the custody information
   */
  public String getCustodyInformation() {
    return custodyInformation;
  }

  /**
   * Returns a textual representation of this file.
   *
   * @return a textual representation of this file
   */
  @Override
  public String toString() {
    return new StringBuilder()
        .append("DG11File [")
        .append(nameOfHolder == null ? "" : nameOfHolder).append(", ")
        .append(otherNames == null || otherNames.isEmpty() ? "[]" : otherNames).append(", ")
        .append(personalNumber == null ? "" : personalNumber).append(", ")
        .append(fullDateOfBirth == null ? "" : fullDateOfBirth).append(", ")
        .append(placeOfBirth == null || placeOfBirth.isEmpty() ? "[]" : placeOfBirth.toString()).append(", ")
        .append(permanentAddress == null || permanentAddress.isEmpty() ? "[]" : permanentAddress.toString()).append(", ")
        .append(telephone == null ? "" : telephone).append(", ")
        .append(profession == null ? "" : profession).append(", ")
        .append(title == null ? "" : title).append(", ")
        .append(personalSummary == null ? "" : personalSummary).append(", ")
        .append(proofOfCitizenship == null ? "" : "image (" + proofOfCitizenship.length + ")").append(", ")
        .append(otherValidTDNumbers == null || otherValidTDNumbers.isEmpty() ? "[]" : otherValidTDNumbers.toString()).append(", ")
        .append(custodyInformation == null ? "" : custodyInformation)
        .append("]")
        .toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    }
    if (obj == this) {
      return true;
    }
    if (!obj.getClass().equals(this.getClass())) {
      return false;
    }
    DG11File other = (DG11File)obj;
    return this.toString().equals(other.toString());
  }

  @Override
  public int hashCode() {
    return 13 * toString().hashCode() + 111;
  }

  /* Reading and writing content of this data group. */

  @Override
  protected void readContent(InputStream inputStream) throws IOException {
    TLVInputStream tlvInputStream = inputStream instanceof TLVInputStream ? (TLVInputStream)inputStream : new TLVInputStream(inputStream);
    int tagListTag = tlvInputStream.readTag();
    if (tagListTag != TAG_LIST_TAG) {
      throw new IllegalArgumentException("Expected tag list in DG11");
    }

    int tagListLength = tlvInputStream.readLength();
    int tagListBytesRead = 0;

    int expectedTagCount = tagListLength / 2;

    ByteArrayInputStream tagListBytesInputStream = new ByteArrayInputStream(tlvInputStream.readValue());
    try {
      /* Find out which tags are present. */
      List<Integer> tagList = new ArrayList<Integer>(expectedTagCount + 1);
      while (tagListBytesRead < tagListLength) {
        /* We're using another TLV inputstream every time to read each tag. */
        TLVInputStream anotherTLVInputStream = new TLVInputStream(tagListBytesInputStream);
        int tag = anotherTLVInputStream.readTag();
        tagListBytesRead += TLVUtil.getTagLength(tag);
        tagList.add(tag);
      }

      /* Now read the fields in order. */
      for (int t: tagList) {
        readField(t, tlvInputStream);
      }
    } finally {
      tagListBytesInputStream.close();
    }
  }

  @Override
  protected void writeContent(OutputStream out) throws IOException {
    TLVOutputStream tlvOut = out instanceof TLVOutputStream ? (TLVOutputStream)out : new TLVOutputStream(out);
    tlvOut.writeTag(TAG_LIST_TAG);
    DataOutputStream dataOut = new DataOutputStream(tlvOut);
    List<Integer> tags = getTagPresenceList();
    for (int tag: tags) {
      dataOut.writeShort(tag);
    }
    dataOut.flush();
    tlvOut.writeValueEnd(); /* TAG_LIST_TAG */
    for (int tag: tags) {
      switch (tag) {
        case FULL_NAME_TAG:
          tlvOut.writeTag(tag);
          tlvOut.writeValue(nameOfHolder.trim().getBytes("UTF-8"));
          break;
        case OTHER_NAME_TAG:
          if (otherNames == null) {
            otherNames = new ArrayList<String>();
          }
          tlvOut.writeTag(CONTENT_SPECIFIC_CONSTRUCTED_TAG);
          tlvOut.writeTag(COUNT_TAG);
          tlvOut.write(otherNames.size());
          tlvOut.writeValueEnd(); /* COUNT_TAG */
          for (String otherName: otherNames) {
            tlvOut.writeTag(OTHER_NAME_TAG);
            tlvOut.writeValue(otherName.trim().getBytes("UTF-8"));
          }
          tlvOut.writeValueEnd(); /* CONTENT_SPECIFIC_CONSTRUCTED_TAG */
          break;
        case PERSONAL_NUMBER_TAG:
          tlvOut.writeTag(tag);
          tlvOut.writeValue(personalNumber.trim().getBytes("UTF-8"));
          break;
        case FULL_DATE_OF_BIRTH_TAG:
          tlvOut.writeTag(tag);
          String fullDateOfBirthString = fullDateOfBirth;
          tlvOut.writeValue(fullDateOfBirthString.getBytes("UTF-8"));
          break;
        case PLACE_OF_BIRTH_TAG:
          tlvOut.writeTag(tag);
          boolean isFirstOne = true;
          for (String detail: placeOfBirth) {
            if (detail != null) {
              if (isFirstOne) {
                isFirstOne = false;
              } else {
                tlvOut.write('<');
              }
              tlvOut.write(detail.trim().getBytes("UTF-8"));
            }
          }
          tlvOut.writeValueEnd(); /* PLACE_OF_BIRTH_TAG */
          break;
        case PERMANENT_ADDRESS_TAG:
          tlvOut.writeTag(tag);
          isFirstOne = true;
          for (String detail: permanentAddress) {
            if (detail != null) {
              if (isFirstOne) {
                isFirstOne = false;
              } else {
                tlvOut.write('<');
              }
              tlvOut.write(detail.trim().getBytes("UTF-8"));
            }
          }
          tlvOut.writeValueEnd(); /* PERMANENT_ADDRESS_TAG */
          break;
        case TELEPHONE_TAG:
          tlvOut.writeTag(tag);
          tlvOut.writeValue(telephone.trim().replace(' ', '<').getBytes("UTF-8"));
          break;
        case PROFESSION_TAG:
          tlvOut.writeTag(tag);
          tlvOut.writeValue(profession.trim().replace(' ', '<').getBytes("UTF-8"));
          break;
        case TITLE_TAG:
          tlvOut.writeTag(tag);
          tlvOut.writeValue(title.trim().replace(' ', '<').getBytes("UTF-8"));
          break;
        case PERSONAL_SUMMARY_TAG:
          tlvOut.writeTag(tag);
          tlvOut.writeValue(personalSummary.trim().replace(' ', '<').getBytes("UTF-8"));
          break;
        case PROOF_OF_CITIZENSHIP_TAG:
          tlvOut.writeTag(tag);
          tlvOut.writeValue(proofOfCitizenship);
          break;
        case OTHER_VALID_TD_NUMBERS_TAG:
          tlvOut.writeTag(tag);
          isFirstOne = true;
          for (String detail: otherValidTDNumbers) {
            if (detail != null) {
              if (isFirstOne) {
                isFirstOne = false;
              } else {
                tlvOut.write('<');
              }
              tlvOut.write(detail.trim().replace(' ', '<').getBytes("UTF-8"));
            }
          }
          tlvOut.writeValueEnd(); /* OTHER_VALID_TD_NUMBERS_TAG */
          break;
        case CUSTODY_INFORMATION_TAG:
          tlvOut.writeTag(tag);
          tlvOut.writeValue(custodyInformation.trim().replace(' ', '<').getBytes("UTF-8"));
          break;
        default: throw new IllegalStateException("Unknown tag in DG11: " + Integer.toHexString(tag));
      }
    }
  }

  /* Field parsing and interpretation below. */

  /**
   * Parses the custody information field.
   *
   * @param value the value of the custody information data object
   */
  private void parseCustodyInformation(byte[] value) {
    try {
      String field = new String(value, "UTF-8");
      //		custodyInformation = in.replace("<", " ").trim();
      custodyInformation = field.trim();
    } catch (UnsupportedEncodingException uee) {
      LOGGER.log(Level.WARNING, "Exception", uee);
      custodyInformation = new String(value).trim();
    }
  }

  /**
   * Parses the other valid travel document numbers field.
   *
   * @param value the value of the other valid travel document numbers data object
   */
  private void parseOtherValidTDNumbers(byte[] value) {
    String field = new String(value).trim();
    try {
      field = new String(value, "UTF-8");
    } catch (UnsupportedEncodingException uee) {
      LOGGER.log(Level.WARNING, "Exception", uee);
    }
    otherValidTDNumbers = new ArrayList<String>();
    StringTokenizer st = new StringTokenizer(field, "<");
    while (st.hasMoreTokens()) {
      String number = st.nextToken().trim();
      otherValidTDNumbers.add(number);
    }
  }

  /**
   * Parses the proof of citizen field.
   *
   * @param value the value of the proof of citizen data object
   */
  private void parseProofOfCitizenShip(byte[] value) {
    proofOfCitizenship = value;
  }

  /**
   * Parses the personal summary field.
   *
   * @param value the value of the personal summary data object
   */
  private void parsePersonalSummary(byte[] value) {
    try {
      String field = new String(value, "UTF-8");
      //		personalSummary = in.replace("<", " ").trim();
      personalSummary = field.trim();
    } catch (UnsupportedEncodingException usee) {
      LOGGER.log(Level.WARNING, "Exception", usee);
      personalSummary = new String(value).trim();
    }
  }

  /**
   * Parses the title field.
   *
   * @param value the value of the title data object
   */
  private void parseTitle(byte[] value) {
    try {
      String field = new String(value, "UTF-8");
      //		title = in.replace("<", " ").trim();
      title = field.trim();
    } catch (UnsupportedEncodingException usee) {
      LOGGER.log(Level.WARNING, "Exception", usee);
      title = new String(value).trim();
    }
  }

  /**
   * Parses the profession field.
   *
   * @param value the value of the profession data object
   */
  private void parseProfession(byte[] value) {
    String field = new String(value);
    try {
      field = new String(value, "UTF-8");
    } catch (UnsupportedEncodingException uee) {
      LOGGER.log(Level.WARNING, "Exception", uee);
    }
    //		profession = in.replace("<", " ").trim();
    profession = field.trim();
  }

  /**
   * Parses the telephone field.
   *
   * @param value the value of the telephone data object
   */
  private void parseTelephone(byte[] value) {
    String field = new String(value);
    try {
      field = new String(value, "UTF-8");
    } catch (UnsupportedEncodingException uee) {
      LOGGER.log(Level.WARNING, "Exception", uee);
    }
    //		telephone = in.replace("<", " ").trim();
    telephone = field.replace("<", " ").trim();
  }

  /**
   * Parses the permanent address field.
   *
   * @param value the value in the permanent address data object
   */
  private void parsePermanentAddress(byte[] value) {
    String field = new String(value);
    try {
      field = new String(value, "UTF-8");
    } catch (UnsupportedEncodingException uee) {
      LOGGER.log(Level.WARNING, "Exception", uee);
    }
    StringTokenizer st = new StringTokenizer(field, "<");
    permanentAddress = new ArrayList<String>();
    while (st.hasMoreTokens()) {
      String line = st.nextToken().trim();
      permanentAddress.add(line);
    }
  }

  /**
   * Parses the place of birth field.
   *
   * @param value the value in the place of birth data object
   */
  private void parsePlaceOfBirth(byte[] value) {
    String field = new String(value);
    try {
      field = new String(value, "UTF-8");
    } catch (UnsupportedEncodingException uee) {
      LOGGER.log(Level.WARNING, "Exception", uee);
    }
    StringTokenizer st = new StringTokenizer(field, "<");
    placeOfBirth = new ArrayList<String>();
    while (st.hasMoreTokens()) {
      String line = st.nextToken().trim();
      placeOfBirth.add(line);
    }
  }

  /**
   * Parses the date of birth.
   *
   * @param value the value of the date of birth data object
   */
  private void parseFullDateOfBirth(byte[] value) {
    String field = null;
    if (value.length == 4) {
      /* Either France or Belgium uses this encoding for dates. */
      field = Hex.bytesToHexString(value);
    } else {
      field = new String(value);
      try {
        field = new String(value, "UTF-8");
      } catch (UnsupportedEncodingException usee) {
        LOGGER.log(Level.WARNING, "Exception", usee);
      }
    }
    fullDateOfBirth = field;
  }

  /**
   * Parses the other name field.
   *
   * @param value the value of the other name data object
   */
  private synchronized void parseOtherName(byte[] value) {
    if (otherNames == null) {
      otherNames = new ArrayList<String>();
    }
    try {
      String field = new String(value, "UTF-8");
      otherNames.add(field.trim());
    } catch (UnsupportedEncodingException usee) {
      LOGGER.log(Level.WARNING, "Exception", usee);
      otherNames.add(new String(value).trim());
    }
  }

  /**
   * Parses the personal number field.
   *
   * @param value the value of the personal number data object
   */
  private void parsePersonalNumber(byte[] value) {
    String field = new String(value);
    try {
      field = new String(value, "UTF-8");
    } catch (UnsupportedEncodingException uee) {
      LOGGER.log(Level.WARNING, "Exception", uee);
    }
    personalNumber = field.trim();
  }

  /**
   * Parses the name of holder field.
   *
   * @param value the value of the name of holder data object
   */
  private void parseNameOfHolder(byte[] value) {
    String field = new String(value);
    try {
      field = new String(value, "UTF-8");
    } catch (UnsupportedEncodingException uee) {
      LOGGER.log(Level.WARNING, "Exception", uee);
    }
    nameOfHolder = field.trim();
  }

  /**
   * Reads a field from a stream.
   *
   * @param expectedFieldTag the tag to expect
   * @param tlvInputStream the stream to read from
   *
   * @throws IOException on error reading from the stream
   */
  private void readField(int expectedFieldTag, TLVInputStream tlvInputStream) throws IOException {
    int tag = tlvInputStream.readTag();
    if (tag == CONTENT_SPECIFIC_CONSTRUCTED_TAG) {
      /* int contentSpecificLength = */ tlvInputStream.readLength();
      int countTag = tlvInputStream.readTag();
      if (countTag != COUNT_TAG) {
        throw new IllegalArgumentException("Expected " + Integer.toHexString(COUNT_TAG) + ", found " + Integer.toHexString(countTag));
      }
      int countLength = tlvInputStream.readLength();
      if (countLength != 1) {
        throw new IllegalArgumentException("Expected length 1 count length, found " + countLength);
      }
      byte[] countValue = tlvInputStream.readValue();
      if (countValue == null || countValue.length != 1) {
        throw new IllegalArgumentException("Number of content specific fields should be encoded in single byte, found " + Arrays.toString(countValue));
      }
      int count = countValue[0] & 0xFF;
      for (int i = 0; i < count; i++) {
        tag = tlvInputStream.readTag();
        if (tag != OTHER_NAME_TAG) {
          throw new IllegalArgumentException("Expected " + Integer.toHexString(OTHER_NAME_TAG) + ", found " + Integer.toHexString(tag));
        }
        /* int otherNameLength = */ tlvInputStream.readLength();
        byte[] value = tlvInputStream.readValue();
        parseOtherName(value);
      }
    } else {
      if (tag != expectedFieldTag) {
        throw new IllegalArgumentException("Expected " + Integer.toHexString(expectedFieldTag) + ", but found " + Integer.toHexString(tag));
      }
      tlvInputStream.readLength();
      byte[] value = tlvInputStream.readValue();
      switch (tag) {
        case FULL_NAME_TAG:
          parseNameOfHolder(value);
          break;
        case OTHER_NAME_TAG:
          parseOtherName(value);
          break;
        case PERSONAL_NUMBER_TAG:
          parsePersonalNumber(value);
          break;
        case FULL_DATE_OF_BIRTH_TAG:
          parseFullDateOfBirth(value);
          break;
        case PLACE_OF_BIRTH_TAG:
          parsePlaceOfBirth(value);
          break;
        case PERMANENT_ADDRESS_TAG:
          parsePermanentAddress(value);
          break;
        case TELEPHONE_TAG:
          parseTelephone(value);
          break;
        case PROFESSION_TAG:
          parseProfession(value);
          break;
        case TITLE_TAG:
          parseTitle(value);
          break;
        case PERSONAL_SUMMARY_TAG:
          parsePersonalSummary(value);
          break;
        case PROOF_OF_CITIZENSHIP_TAG:
          parseProofOfCitizenShip(value);
          break;
        case OTHER_VALID_TD_NUMBERS_TAG:
          parseOtherValidTDNumbers(value);
          break;
        case CUSTODY_INFORMATION_TAG:
          parseCustodyInformation(value);
          break;
        default:
          throw new IllegalArgumentException("Unknown field tag in DG11: " + Integer.toHexString(tag));
      }
    }
  }
}
