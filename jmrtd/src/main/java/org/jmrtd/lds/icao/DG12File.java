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
 * $Id: DG12File.java 1802 2018-11-06 16:29:28Z martijno $
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
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.lds.DataGroup;

import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVOutputStream;
import net.sf.scuba.tlv.TLVUtil;
import net.sf.scuba.util.Hex;

/**
 * File structure for the EF_DG12 file.
 * Datagroup 12 contains additional document detail(s).
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1802 $
 */
public class DG12File extends DataGroup {

  private static final long serialVersionUID = -1979367459379125674L;

  private static final int TAG_LIST_TAG = 0x5C;

  public static final int ISSUING_AUTHORITY_TAG = 0x5F19;
  public static final int DATE_OF_ISSUE_TAG = 0x5F26;  // yyyymmdd
  public static final int NAME_OF_OTHER_PERSON_TAG = 0x5F1A; // formatted per ICAO 9303 rules
  public static final int ENDORSEMENTS_AND_OBSERVATIONS_TAG = 0x5F1B;
  public static final int TAX_OR_EXIT_REQUIREMENTS_TAG = 0x5F1C;
  public static final int IMAGE_OF_FRONT_TAG = 0x5F1D; // Image per ISO/IEC 10918
  public static final int IMAGE_OF_REAR_TAG = 0x5F1E; // Image per ISO/IEC 10918
  public static final int DATE_AND_TIME_OF_PERSONALIZATION_TAG = 0x5F55; // yyyymmddhhmmss
  public static final int PERSONALIZATION_SYSTEM_SERIAL_NUMBER_TAG = 0x5F56;
  public static final int CONTENT_SPECIFIC_CONSTRUCTED_TAG = 0xA0; // 5F1A is always used inside A0 constructed object
  public static final int COUNT_TAG = 0x02; // Used in A0 constructed object to indicate single byte count of simple objects

  private static final String SDF = "yyyyMMdd";
  private static final String SDTF = "yyyyMMddhhmmss";

  private String issuingAuthority;
  private String dateOfIssue;
  private List<String> namesOfOtherPersons;
  private String endorsementsAndObservations;
  private String taxOrExitRequirements;
  private byte[] imageOfFront;
  private byte[] imageOfRear;
  private String dateAndTimeOfPersonalization;
  private String personalizationSystemSerialNumber;

  private List<Integer> tagPresenceList;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /**
   * Constructs a new file.
   *
   * @param issuingAuthority the issuing authority
   * @param dateOfIssue the date of issue
   * @param namesOfOtherPersons names of other persons
   * @param endorsementsAndObservations endorsements and observations
   * @param taxOrExitRequirements tax or exit requirements
   * @param imageOfFront image of front
   * @param imageOfRear image of rear
   * @param dateAndTimeOfPersonalization date and time of personalization
   * @param personalizationSystemSerialNumber personalization system serial number
   */
  public DG12File(String issuingAuthority, Date dateOfIssue,
      List<String> namesOfOtherPersons, String endorsementsAndObservations,
      String taxOrExitRequirements, byte[] imageOfFront,
      byte[] imageOfRear, Date dateAndTimeOfPersonalization,
      String personalizationSystemSerialNumber) {
    this(issuingAuthority, new SimpleDateFormat(SDF).format(dateOfIssue),
        namesOfOtherPersons, endorsementsAndObservations,
        taxOrExitRequirements, imageOfFront,
        imageOfRear, new SimpleDateFormat(SDTF).format(dateAndTimeOfPersonalization),
        personalizationSystemSerialNumber);
  }

  /**
   * Constructs a new file.
   *
   * @param issuingAuthority the issuing authority
   * @param dateOfIssue the date of issue
   * @param namesOfOtherPersons names of other persons
   * @param endorsementsAndObservations endorsements and observations
   * @param taxOrExitRequirements tax or exit requirements
   * @param imageOfFront image of front
   * @param imageOfRear image of rear
   * @param dateAndTimeOfPersonalization date and time of personalization
   * @param personalizationSystemSerialNumber personalization system serial number
   */
  public DG12File(String issuingAuthority, String dateOfIssue,
      List<String> namesOfOtherPersons, String endorsementsAndObservations,
      String taxOrExitRequirements, byte[] imageOfFront,
      byte[] imageOfRear, String dateAndTimeOfPersonalization,
      String personalizationSystemSerialNumber) {
    super(EF_DG12_TAG);
    this.issuingAuthority = issuingAuthority;
    this.dateOfIssue = dateOfIssue;
    this.namesOfOtherPersons = namesOfOtherPersons == null ? new ArrayList<String>() : new ArrayList<String>(namesOfOtherPersons);
    this.endorsementsAndObservations = endorsementsAndObservations;
    this.taxOrExitRequirements = taxOrExitRequirements;
    this.imageOfFront = imageOfFront;
    this.imageOfRear = imageOfRear;
    this.dateAndTimeOfPersonalization = dateAndTimeOfPersonalization;
    this.personalizationSystemSerialNumber = personalizationSystemSerialNumber;
  }

  /**
   * Constructs a new file.
   *
   * @param inputStream an input stream
   *
   * @throws IOException on error reading from input stream
   */
  public DG12File(InputStream inputStream) throws IOException {
    super(EF_DG12_TAG, inputStream);
  }

  @Override
  protected void readContent(InputStream inputStream) throws IOException {
    TLVInputStream tlvInputStream = inputStream instanceof TLVInputStream ? (TLVInputStream)inputStream : new TLVInputStream(inputStream);
    int tagListTag = tlvInputStream.readTag();
    if (tagListTag != TAG_LIST_TAG) {
      throw new IllegalArgumentException("Expected tag list in DG12");
    }

    int tagListLength = tlvInputStream.readLength();
    int tagListBytesRead = 0;

    int expectedTagCount = tagListLength / 2;

    ByteArrayInputStream tagListBytesInputStream = new ByteArrayInputStream(tlvInputStream.readValue());
    try {
      /* Find out which tags are present. */
      List<Integer> tagList = new ArrayList<Integer>(expectedTagCount + 1);
      while (tagListBytesRead < tagListLength) {
        /* We're using another TLV inputstream everytime to read each tag. */
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
  protected void writeContent(OutputStream outputStream) throws IOException {
    TLVOutputStream tlvOut = outputStream instanceof TLVOutputStream ? (TLVOutputStream)outputStream : new TLVOutputStream(outputStream);
    tlvOut.writeTag(TAG_LIST_TAG);
    List<Integer> tags = getTagPresenceList();
    DataOutputStream dataOut = new DataOutputStream(tlvOut);
    for (int tag: tags) {
      dataOut.writeShort(tag);
    }
    dataOut.flush();
    tlvOut.writeValueEnd(); /* TAG_LIST_TAG */
    for (int tag: tags) {
      switch (tag) {
        case ISSUING_AUTHORITY_TAG:
          tlvOut.writeTag(tag);
          tlvOut.writeValue(issuingAuthority.trim().getBytes("UTF-8"));
          break;
        case DATE_OF_ISSUE_TAG:
          tlvOut.writeTag(tag);
          tlvOut.writeValue(dateOfIssue.getBytes("UTF-8"));
          break;
        case NAME_OF_OTHER_PERSON_TAG:
          if (namesOfOtherPersons == null) {
            namesOfOtherPersons = new ArrayList<String>();
          }
          tlvOut.writeTag(CONTENT_SPECIFIC_CONSTRUCTED_TAG);
          tlvOut.writeTag(COUNT_TAG);
          tlvOut.write(namesOfOtherPersons.size());
          tlvOut.writeValueEnd(); /* COUNT_TAG */
          for (String nameOfOtherPerson: namesOfOtherPersons) {
            tlvOut.writeTag(NAME_OF_OTHER_PERSON_TAG);
            tlvOut.writeValue(nameOfOtherPerson.trim().getBytes("UTF-8"));
          }
          tlvOut.writeValueEnd(); /* CONTENT_SPECIFIC_CONSTRUCTED_TAG */
          break;
        case ENDORSEMENTS_AND_OBSERVATIONS_TAG:
          tlvOut.writeTag(tag);
          tlvOut.writeValue(endorsementsAndObservations.trim().getBytes("UTF-8"));
          break;
        case TAX_OR_EXIT_REQUIREMENTS_TAG:
          tlvOut.writeTag(tag);
          tlvOut.writeValue(taxOrExitRequirements.trim().getBytes("UTF-8"));
          break;
        case IMAGE_OF_FRONT_TAG:
          tlvOut.writeTag(tag);
          tlvOut.writeValue(imageOfFront);
          break;
        case IMAGE_OF_REAR_TAG:
          tlvOut.writeTag(tag);
          tlvOut.writeValue(imageOfRear);
          break;
        case DATE_AND_TIME_OF_PERSONALIZATION_TAG:
          tlvOut.writeTag(tag);
          tlvOut.writeValue(dateAndTimeOfPersonalization.getBytes("UTF-8"));
          break;
        case PERSONALIZATION_SYSTEM_SERIAL_NUMBER_TAG:
          tlvOut.writeTag(tag);
          tlvOut.writeValue(personalizationSystemSerialNumber.trim().getBytes("UTF-8"));
          break;
        default:
          throw new IllegalArgumentException("Unknown field tag in DG12: " + Integer.toHexString(tag));
      }
    }
  }

  /**
   * Returns the tags of fields actually present in this file.
   *
   * @return a list of tags
   */
  public List<Integer> getTagPresenceList() {
    if (tagPresenceList != null) {
      return tagPresenceList;
    }
    tagPresenceList = new ArrayList<Integer>(10);
    if (issuingAuthority != null) {
      tagPresenceList.add(ISSUING_AUTHORITY_TAG);
    }
    if (dateOfIssue != null) {
      tagPresenceList.add(DATE_OF_ISSUE_TAG);
    }
    if (namesOfOtherPersons != null && !namesOfOtherPersons.isEmpty()) {
      tagPresenceList.add(NAME_OF_OTHER_PERSON_TAG);
    }
    if (endorsementsAndObservations != null) {
      tagPresenceList.add(ENDORSEMENTS_AND_OBSERVATIONS_TAG);
    }
    if (taxOrExitRequirements != null) {
      tagPresenceList.add(TAX_OR_EXIT_REQUIREMENTS_TAG);
    }
    if (imageOfFront != null) {
      tagPresenceList.add(IMAGE_OF_FRONT_TAG);
    }
    if (imageOfRear != null) {
      tagPresenceList.add(IMAGE_OF_REAR_TAG);
    }
    if (dateAndTimeOfPersonalization != null) {
      tagPresenceList.add(DATE_AND_TIME_OF_PERSONALIZATION_TAG);
    }
    if (personalizationSystemSerialNumber != null) {
      tagPresenceList.add(PERSONALIZATION_SYSTEM_SERIAL_NUMBER_TAG);
    }
    return tagPresenceList;
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
        if (tag != NAME_OF_OTHER_PERSON_TAG) {
          throw new IllegalArgumentException("Expected " + Integer.toHexString(NAME_OF_OTHER_PERSON_TAG) + ", found " + Integer.toHexString(tag));
        }
        /* int otherPersonFieldLength = */ tlvInputStream.readLength();
        byte[] value = tlvInputStream.readValue();
        parseNameOfOtherPerson(value);
      }
    } else {
      if (tag != expectedFieldTag) {
        throw new IllegalArgumentException("Expected " + Integer.toHexString(expectedFieldTag) + ", but found " + Integer.toHexString(tag));
      }
      /* int length = */ tlvInputStream.readLength();
      byte[] value = tlvInputStream.readValue();
      switch (tag) {
        case ISSUING_AUTHORITY_TAG:
          parseIssuingAuthority(value);
          break;
        case DATE_OF_ISSUE_TAG:
          parseDateOfIssue(value);
          break;
        case NAME_OF_OTHER_PERSON_TAG:
          parseNameOfOtherPerson(value);
          break;
        case ENDORSEMENTS_AND_OBSERVATIONS_TAG:
          parseEndorsementsAndObservations(value);
          break;
        case TAX_OR_EXIT_REQUIREMENTS_TAG:
          parseTaxOrExitRequirements(value);
          break;
        case IMAGE_OF_FRONT_TAG:
          parseImageOfFront(value);
          break;
        case IMAGE_OF_REAR_TAG:
          parseImageOfRear(value);
          break;
        case DATE_AND_TIME_OF_PERSONALIZATION_TAG:
          parseDateAndTimeOfPersonalization(value);
          break;
        case PERSONALIZATION_SYSTEM_SERIAL_NUMBER_TAG:
          parsePersonalizationSystemSerialNumber(value);
          break;
        default:
          throw new IllegalArgumentException("Unknown field tag in DG12: " + Integer.toHexString(tag));
      }
    }
  }

  /* Accessors below. */

  /**
   * Returns the issuing authority.
   *
   * @return the issuingAuthority
   */
  public String getIssuingAuthority() {
    return issuingAuthority;
  }

  /**
   * Returns the date of issuance.
   *
   * @return the dateOfIssue
   */
  public String getDateOfIssue() {
    return dateOfIssue;
  }

  /**
   * Returns name of other person.
   *
   * @return the nameOfOtherPerson
   */
  public List<String> getNamesOfOtherPersons() {
    return namesOfOtherPersons;
  }

  /**
   * Returns endorsements and observations.
   *
   * @return the endorsementsAndObservations
   */
  public String getEndorsementsAndObservations() {
    return endorsementsAndObservations;
  }

  /**
   * Returns tax or exit requirements.
   *
   * @return the taxOrExitRequirements
   */
  public String getTaxOrExitRequirements() {
    return taxOrExitRequirements;
  }

  /**
   * Returns image of front.
   *
   * @return the imageOfFront
   */
  public byte[] getImageOfFront() {
    return imageOfFront;
  }

  /**
   * Returns image of rear.
   *
   * @return the imageOfRear
   */
  public byte[] getImageOfRear() {
    return imageOfRear;
  }

  /**
   * Returns the date and time of personalization.
   *
   * @return the dateAndTimeOfPersonalization
   */
  public String getDateAndTimeOfPersonalization() {
    return dateAndTimeOfPersonalization;
  }

  /**
   * Returns the personalization system serial number.
   *
   * @return the personalizationSystemSerialNumber
   */
  public String getPersonalizationSystemSerialNumber() {
    return personalizationSystemSerialNumber;
  }

  @Override
  public int getTag() {
    return EF_DG12_TAG;
  }

  /**
   * Returns a textual representation of this file.
   *
   * @return a textual representation of this file
   */
  @Override
  public String toString() {
    return new StringBuilder()
        .append("DG12File [")
        .append(issuingAuthority == null ? "" : issuingAuthority).append(", ")
        .append(dateOfIssue == null ? "" : dateOfIssue).append(", ")
        .append(namesOfOtherPersons == null || namesOfOtherPersons.isEmpty() ? "" : namesOfOtherPersons).append(", ")
        .append(endorsementsAndObservations == null ? "" : endorsementsAndObservations).append(", ")
        .append(taxOrExitRequirements == null ? "" : taxOrExitRequirements).append(", ")
        .append(imageOfFront == null ? "" : "image (" + imageOfFront.length + ")").append(", ")
        .append(imageOfRear == null ? "" : "image (" + imageOfRear.length + ")").append(", ")
        .append(dateAndTimeOfPersonalization == null ? "" : dateAndTimeOfPersonalization).append(", ")
        .append(personalizationSystemSerialNumber== null ? "" : personalizationSystemSerialNumber)
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
    DG12File other = (DG12File)obj;
    return this.toString().equals(other.toString());
  }

  @Override
  public int hashCode() {
    return 13 * toString().hashCode() + 112;
  }

  /* Field parsing below. */

  /**
   * Parses the personalization system serial number.
   *
   * @param value the value of the personalization system serial number
   */
  private void parsePersonalizationSystemSerialNumber(byte[] value) {
    try {
      String field = new String(value, "UTF-8");
      personalizationSystemSerialNumber = field.trim();
    } catch (UnsupportedEncodingException usee) {
      /* NOTE: UTF-8 not supported? Unlikely. In any case use default charset. */
      LOGGER.log(Level.WARNING, "Exception", usee);
      personalizationSystemSerialNumber = new String(value).trim();
    }
  }

  /**
   * Parses the date and time of personalization.
   *
   * @param value the value of the date and time of personalization data object
   */
  private void parseDateAndTimeOfPersonalization(byte[] value) {
    try {
      String field = new String(value, "UTF-8");
      dateAndTimeOfPersonalization = field.trim();
    } catch (UnsupportedEncodingException usee) {
      /* NOTE: never happens, UTF-8 is supported. */
      LOGGER.log(Level.WARNING, "Exception", usee);
    }
  }

  /**
   * Parses the image of front field.
   *
   * @param value the value of the image of front data object
   */
  private void parseImageOfFront(byte[] value) {
    imageOfFront =  value;
  }

  /**
   * Parses the image of rear field.
   *
   * @param value the value of the image of read data object
   */
  private void parseImageOfRear(byte[] value) {
    imageOfRear =  value;
  }

  /**
   * Parses the tax or exit requirements.
   *
   * @param value the value of the tax or exit requirements data object
   */
  private void parseTaxOrExitRequirements(byte[] value) {
    try {
      String field = new String(value, "UTF-8");
      taxOrExitRequirements = field.trim();
    } catch (UnsupportedEncodingException usee) {
      /* NOTE: UTF-8 not supported? Unlikely. In any case use default charset. */
      LOGGER.log(Level.WARNING, "Exception", usee);
      taxOrExitRequirements = new String(value).trim();
    }
  }

  /**
   * Parses the endorsements and observations field.
   *
   * @param value the value of the endorsements and observations data object
   */
  private void parseEndorsementsAndObservations(byte[] value) {
    try {
      String field = new String(value, "UTF-8");
      endorsementsAndObservations = field.trim();
    } catch (UnsupportedEncodingException usee) {
      /* NOTE: UTF-8 not supported? Unlikely. In any case use default charset. */
      LOGGER.log(Level.WARNING, "Exception", usee);
      endorsementsAndObservations = new String(value).trim();
    }
  }

  /**
   * Parses the name of other person field.
   *
   * @param value the value of the name of other person data object
   */
  private synchronized void parseNameOfOtherPerson(byte[] value) {
    if (namesOfOtherPersons == null) {
      namesOfOtherPersons = new ArrayList<String>();
    }
    try {
      String field = new String(value, "UTF-8");
      namesOfOtherPersons.add(field.trim());
    } catch (UnsupportedEncodingException usee) {
      /* NOTE: UTF-8 not supported? Unlikely. In any case use default charset. */
      LOGGER.log(Level.WARNING, "Exception", usee);
      namesOfOtherPersons.add(new String(value).trim());
    }
  }

  /**
   * Parses the data of issue field.
   *
   * @param value the value of the date of issue data object
   */
  private void parseDateOfIssue(byte[] value) {
    if (value == null) {
      throw new IllegalArgumentException("Wrong date format");
    }

    /* Try to interpret value as a ccyymmdd formatted date string as per Doc 9303. */
    if (value.length == 8) {
      try {
        String dateString = new String(value, "UTF-8");
        dateOfIssue = dateString.trim();
        return;
      } catch (UnsupportedEncodingException usee) {
        /* NOTE: never happens, UTF-8 is supported. */
        LOGGER.log(Level.WARNING, "Exception", usee);
      }
    }
    LOGGER.warning("DG12 date of issue is not in expected ccyymmdd ASCII format");

    /* Some live French MRTDs encode the date as ccyymmdd but in BCD, not in ASCII. */
    if (value.length == 4) {
      String dateString = Hex.bytesToHexString(value);
      dateOfIssue = dateString.trim();
      return;
    }

    /* Giving up... we can't parse this date. */
    throw new IllegalArgumentException("Wrong date format");
  }

  /**
   * Parses the issuing authority field.
   *
   * @param value the value of the issuing authority data object
   */
  private void parseIssuingAuthority(byte[] value) {
    try {
      String field = new String(value, "UTF-8");
      issuingAuthority = field.trim();
    } catch (UnsupportedEncodingException usee) {
      /* NOTE: Default charset, wtf, UTF-8 not supported? */
      LOGGER.log(Level.WARNING, "Exception", usee);
      issuingAuthority = (new String(value)).trim();
    }
  }
}
