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
 * $Id: ICAOCountry.java 1765 2018-02-19 21:49:52Z martijno $
 */

package org.jmrtd.lds.icao;

import java.util.logging.Level;
import java.util.logging.Logger;

import net.sf.scuba.data.Country;

/**
 * Special ICAO countries not covered in {@link net.sf.scuba.data.ISOCountry}.
 * Contributed by Aleksandar Kamburov (wise_guybg).
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1765 $
 */
public class ICAOCountry extends Country {

  private static final long serialVersionUID = 2942942609311086138L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  public static final ICAOCountry DE = new ICAOCountry("DE", "D<<", "Germany", "German");

  public static final ICAOCountry GBD = new ICAOCountry("GB","GBD","British Dependent territories citizen");
  public static final ICAOCountry GBN = new ICAOCountry("GB","GBN","British National (Overseas)");
  public static final ICAOCountry GBO = new ICAOCountry("GB","GBO","British Overseas citizen");
  public static final ICAOCountry GBP = new ICAOCountry("GB","GBP","British Protected person");
  public static final ICAOCountry GBS = new ICAOCountry("GB","GBS","British Subject");

  public static final ICAOCountry XXA = new ICAOCountry("XX","XXA","Stateless person", "Stateless");
  public static final ICAOCountry XXB = new ICAOCountry("XX","XXB","Refugee", "Refugee");
  public static final ICAOCountry XXC = new ICAOCountry("XX","XXC","Refugee (other)", "Refugee (other)");
  public static final ICAOCountry XXX = new ICAOCountry("XX","XXX","Unspecified", "Unspecified");

  /** Part B: Europe. */
  public static final ICAOCountry EUE = new ICAOCountry("EU", "EUE", "Europe", "European");

  /** Part C: Codes for Use in United Nations Travel Documents. */
  public static final ICAOCountry UNO = new ICAOCountry("UN","UNO","United Nations Organization");
  public static final ICAOCountry UNA = new ICAOCountry("UN","UNA","United Nations Agency");
  public static final ICAOCountry UNK = new ICAOCountry("UN","UNK","United Nations Interim Administration Mission in Kosovo");

  /** Part D: Other issuing authorities. */
  public static final ICAOCountry XBA = new ICAOCountry("XX", "XBA", "African Development Bank (ADB)");
  public static final ICAOCountry XIM = new ICAOCountry("XX", "XIM", "African Export-Import Bank (AFREXIM bank)");
  public static final ICAOCountry XCC = new ICAOCountry("XC","XCC","Carribean Community or one of its emissaries (CARICOM)");
  public static final ICAOCountry XCO = new ICAOCountry("XX", "XCO", "Common Market for Eastern an Southern Africa (COMESA)");
  public static final ICAOCountry XEC = new ICAOCountry("XX", "XEC", "Economic Community of West African States (ECOWAS)");
  public static final ICAOCountry XPO = new ICAOCountry("XP", "XPO", "International Criminal Police Organization (INTERPOL)");
  public static final ICAOCountry XOM = new ICAOCountry("XO","XOM","Sovereign Military Order of Malta or one of its emissaries");

  private static final ICAOCountry[] VALUES = {
      DE,
      GBD, GBN, GBO, GBP, GBS,
      XXA, XXB, XXC, XXX,
      EUE,
      UNO, UNA, UNK,
      XBA, XIM, XCC, XCO, XEC, XPO, XOM
  };

  private String name;
  private String nationality;
  private String alpha2Code;
  private String alpha3Code;

  /**
   * Prevent caller from creating instance.
   */
  private ICAOCountry() {
  }

  /**
   * Constructs a country.
   *
   * @param alpha2Code the two-digit alpha code
   * @param alpha3Code the three-digit alpha code
   * @param name a name for the country
   *        (which will also be used to indicate the nationality of the country)
   */
  private ICAOCountry(String alpha2Code, String alpha3Code, String name) {
    this(alpha2Code, alpha3Code, name, name);
  }

  /**
   * Constructs a country.
   *
   * @param alpha2Code the 2-letter alpha code
   * @param alpha3Code the 3-letter alpha code
   * @param name a name for the country
   * @param nationality a name for nationals of the country
   */
  private ICAOCountry(String alpha2Code, String alpha3Code, String name, String nationality) {
    this.alpha2Code = alpha2Code;
    this.alpha3Code = alpha3Code;
    this.name = name;
    this.nationality = nationality;
  }

  /**
   * Returns an ICAO country instance.
   *
   * @param alpha3Code a three-digit ICAO country code
   *
   * @return an ICAO country
   */
  public static Country getInstance(String alpha3Code) {
    for (ICAOCountry country: VALUES) {
      if (country.alpha3Code.equals(alpha3Code)) {
        return country;
      }
    }
    try {
      return Country.getInstance(alpha3Code);
    } catch (Exception e) {
      /* NOTE: ignore this exception if it's not a legal 3 digit code. */
      LOGGER.log(Level.FINE, "Unknown country", e);
    }
    throw new IllegalArgumentException("Illegal ICAO country alpha 3 code " + alpha3Code);
  }

  @Override
  public int valueOf() {
    return -1;
  }

  /**
   * Returns the full name of the country.
   *
   * @return a country name
   */
  @Override
  public String getName() {
    return name;
  }

  /**
   * Returns the adjectival form corresponding to the country.
   *
   * @return the nationality
   */
  @Override
  public String getNationality() {
    return nationality;
  }

  /**
   * Returns the two-digit country code.
   *
   * @return a two-digit country code
   */
  @Override
  public String toAlpha2Code() {
    return alpha2Code;
  }

  /**
   * Returns the three-digit country code.
   *
   * @return a three-digit country code
   */
  @Override
  public String toAlpha3Code() {
    return alpha3Code;
  }
}
