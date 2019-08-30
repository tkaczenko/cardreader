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
 * $Id: CVCPrincipal.java 1808 2019-03-07 21:32:19Z martijno $
 */

package org.jmrtd.cert;

import java.io.Serializable;
import java.security.Principal;
import java.util.logging.Level;
import java.util.logging.Logger;

import net.sf.scuba.data.Country;

/**
 * Card verifiable certificate principal.
 * This just wraps the EJBCA implementation.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1808 $
 */
public class CVCPrincipal implements Principal, Serializable {

  private static final long serialVersionUID = -4905647207367309688L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private Country country;
  private String mnemonic;
  private String seqNumber;

  /**
   * Constructs a principal.
   *
   * @param name a name with format Country (2F) | Mnemonic (9V) | SeqNum (5F).
   */
  public CVCPrincipal(String name) {
    if (name == null) {
      throw new IllegalArgumentException("Name should be <Country (2F)><Mnemonic (9V)><SeqNum (5F)> formatted, found null");
    }
    if (name.length() < 2 + 5 || name.length() > 2 + 9 + 5) {
      throw new IllegalArgumentException("Name should be <Country (2F)><Mnemonic (9V)><SeqNum (5F)> formatted, found \"" + name + "\"");
    }

    final String alpha2Code = name.substring(0, 2).toUpperCase();
    try {
      country = Country.getInstance(alpha2Code);
    } catch (IllegalArgumentException iae) {
      LOGGER.log(Level.FINE, "Could not find country for " + alpha2Code, iae);
      country = new Country() {

        private static final long serialVersionUID = 345841304964161797L;

        @Override
        public int valueOf() {
          return -1;
        }

        @Override
        public String getName() {
          return "Unknown";
        }

        @Override
        public String getNationality() {
          return "Unknown";
        }

        @Override
        public String toAlpha2Code() {
          return alpha2Code;
        }

        @Override
        public String toAlpha3Code() {
          return "XXX";
        }

      };
    }
    mnemonic = name.substring(2, name.length() - 5);
    seqNumber = name.substring(name.length() - 5, name.length());
  }

  /**
   * Constructs a principal.
   *
   * @param country the country
   * @param mnemonic the mnemonic
   * @param seqNumber the sequence number
   */
  public CVCPrincipal(Country country, String mnemonic, String seqNumber) {
    if (mnemonic == null || mnemonic.length() > 9) {
      throw new IllegalArgumentException("Wrong length mnemonic");
    }
    if (seqNumber == null || seqNumber.length() != 5) {
      throw new IllegalArgumentException("Wrong length seqNumber");
    }
    this.country = country;
    this.mnemonic = mnemonic;
    this.seqNumber = seqNumber;
  }

  /**
   * Consists of the concatenation of
   * country code (length 2), mnemonic (length &lt; 9) and
   * sequence number (length 5).
   *
   * @return the name of the principal
   */
  public String getName() {
    return country.toAlpha2Code() + mnemonic + seqNumber;
  }

  /**
   * Returns a textual representation of this principal.
   *
   * @return a textual representation of this principal
   */
  @Override
  public String toString() {
    return country.toAlpha2Code() + "/" + mnemonic + "/" + seqNumber;
  }

  /**
   * Returns the country.
   *
   * @return the country
   */
  public Country getCountry() {
    return country;
  }

  /**
   * Returns the mnemonic.
   *
   * @return the mnemonic
   */
  public String getMnemonic() {
    return mnemonic;
  }

  /**
   * Returns the sequence number.
   *
   * @return the seqNumber
   */
  public String getSeqNumber() {
    return seqNumber;
  }

  /**
   * Tests for equality with respect to another object.
   *
   * @param otherObj another object
   *
   * @return whether this principal equals the other object
   */
  @Override
  public boolean equals(Object otherObj) {
    if (otherObj == null) {
      return false;
    }
    if (otherObj == this) {
      return true;
    }
    if (!otherObj.getClass().equals(this.getClass())) {
      return false;
    }

    CVCPrincipal otherPrincipal = (CVCPrincipal)otherObj;
    return otherPrincipal.country.equals(this.country)
        && otherPrincipal.mnemonic.equals(this.mnemonic)
        && otherPrincipal.seqNumber.equals(this.seqNumber);
  }

  /**
   * Returns a hash code of this object.
   *
   * @return the hash code
   */
  @Override
  public int hashCode() {
    return 2 * getName().hashCode() + 1231211;
  }
}
