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
 * $Id: ComplexCBEFFInfo.java 1808 2019-03-07 21:32:19Z martijno $
 */

package org.jmrtd.cbeff;

import java.util.ArrayList;
import java.util.List;

/**
 * Complex (nested) CBEFF BIR.
 * Specified in ISO 19785-1 (version 2.0) and NISTIR 6529-A (version 1.1).
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1808 $
 *
 * @since 0.4.7
 */
public class ComplexCBEFFInfo implements CBEFFInfo {

  private List<CBEFFInfo> subRecords;

  /**
   * Constructs a default complex info, with an empty list of sub-records.
   */
  public ComplexCBEFFInfo() {
    this.subRecords = new ArrayList<CBEFFInfo>();
  }

  /**
   * Returns the records inside this complex CBEFF info.
   *
   * @return a list of CBEFF infos
   */
  public List<CBEFFInfo> getSubRecords() {
    return new ArrayList<CBEFFInfo>(this.subRecords);
  }

  /**
   * Adds a record to this complex CBEFF info.
   *
   * @param subRecord the CBEFF info to add
   */
  public void add(CBEFFInfo subRecord) {
    this.subRecords.add(subRecord);
  }

  /**
   * Adds all records in a list to this complex CBEFF info.
   *
   * @param subRecords a list of CBEFF infos
   */
  public void addAll(List<CBEFFInfo> subRecords) {
    this.subRecords.addAll(subRecords);
  }

  /**
   * Removes a record in this complex CBEFF info.
   *
   * @param index the index of the CBEFF info to remove
   */
  public void remove(int index) {
    this.subRecords.remove(index);
  }

  /**
   * Tests whether the parameter equals this complex CBEFF info.
   *
   * @param other some other object
   *
   * @return whether the other object is equal to this complex CBEFF info
   */
  @Override
  public boolean equals(Object other) {
    if (other == null) {
      return false;
    }
    if (other == this) {
      return true;
    }
    if (!(other.getClass().equals(ComplexCBEFFInfo.class))) {
      return false;
    }

    ComplexCBEFFInfo otherRecord = (ComplexCBEFFInfo)other;
    return subRecords.equals(otherRecord.getSubRecords());
  }

  /**
   * Computes a hash code.
   *
   * @return the hash code for this complex CBEFF info
   */
  @Override
  public int hashCode() {
    return 7 * subRecords.hashCode() + 11;
  }
}
