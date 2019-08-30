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
 * $Id: DG14File.java 1809 2019-05-21 09:52:27Z martijno $
 */

package org.jmrtd.lds.icao;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DLSet;
import org.jmrtd.lds.ActiveAuthenticationInfo;
import org.jmrtd.lds.ChipAuthenticationInfo;
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo;
import org.jmrtd.lds.DataGroup;
import org.jmrtd.lds.SecurityInfo;
import org.jmrtd.lds.TerminalAuthenticationInfo;

/**
 * Data Group 14 stores a set of SecurityInfos for EAC and PACE, see
 * BSI EAC 1.11 and ICAO TR-SAC-1.01.
 * To us the interesting bits are: the map of public keys (EC or DH),
 * the map of protocol identifiers which should match the key's map (not
 * checked here!), and the file identifier of the efCVCA file.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1809 $
 */
public class DG14File extends DataGroup {

  private static final long serialVersionUID = -3536507558193769953L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /** The security infos that make up this file. */
  private Set<SecurityInfo> securityInfos;

  /**
   * Constructs a new DG14 file from the provided data.
   *
   * @param securityInfos a list of security infos
   */
  public DG14File(Collection<SecurityInfo> securityInfos) {
    super(EF_DG14_TAG);
    if (securityInfos == null) {
      throw new IllegalArgumentException("Null securityInfos");
    }
    this.securityInfos = new HashSet<SecurityInfo>(securityInfos);
  }

  /**
   * Constructs a new DG14 file from the data in an input stream.
   *
   * @param inputStream the input stream to parse the data from
   *
   * @throws IOException on error reading from input stream
   */
  public DG14File(InputStream inputStream) throws IOException {
    super(EF_DG14_TAG, inputStream);
  }

  @Override
  protected void readContent(InputStream inputStream) throws IOException {
    securityInfos = new HashSet<SecurityInfo>();
    ASN1InputStream asn1In = new ASN1InputStream(inputStream);
    ASN1Set set = (ASN1Set)asn1In.readObject();
    for (int i = 0; i < set.size(); i++) {
      ASN1Primitive object = set.getObjectAt(i).toASN1Primitive();
      try {
        SecurityInfo securityInfo = SecurityInfo.getInstance(object);
        if (securityInfo == null) {
          LOGGER.warning("Skipping this unsupported SecurityInfo");
          continue;
        }
        securityInfos.add(securityInfo);
      } catch (Exception e) {
        LOGGER.log(Level.WARNING, "Skipping Security Info", e);
      }
    }
  }

  /* FIXME: rewrite (using writeObject instead of getDERObject) to remove interface dependency on BC. */
  @Override
  protected void writeContent(OutputStream outputStream) throws IOException {
    ASN1EncodableVector vector = new ASN1EncodableVector();
    for (SecurityInfo securityInfo: securityInfos) {
      if (securityInfo == null) {
        continue;
      }

      ASN1Primitive derObject = securityInfo.getDERObject();
      vector.add(derObject);
    }
    ASN1Set derSet = new DLSet(vector);
    outputStream.write(derSet.getEncoded(ASN1Encoding.DER));
  }

  /**
   * Returns the  Terminal Authentication infos.
   *
   * @return the Terminal Authentication infos.
   *
   * @deprecated Clients should use {@link #getSecurityInfos()} and filter that collection
   */
  @Deprecated
  public List<TerminalAuthenticationInfo> getTerminalAuthenticationInfos() {
    List<TerminalAuthenticationInfo> terminalAuthenticationInfos = new ArrayList<TerminalAuthenticationInfo>();
    for (SecurityInfo securityInfo: securityInfos) {
      if (securityInfo instanceof TerminalAuthenticationInfo) {
        terminalAuthenticationInfos.add((TerminalAuthenticationInfo)securityInfo);
      }
    }
    return terminalAuthenticationInfos;
  }

  /**
   * Returns the Chip Authentication infos.
   *
   * @return the Chip Authentication infos
   *
   * @deprecated Clients should use {@link #getSecurityInfos()} and filter that collection
   */
  @Deprecated
  public List<ChipAuthenticationInfo> getChipAuthenticationInfos() {
    List<ChipAuthenticationInfo> map = new ArrayList<ChipAuthenticationInfo>();
    for (SecurityInfo securityInfo: securityInfos) {
      if (securityInfo instanceof ChipAuthenticationInfo) {
        ChipAuthenticationInfo chipAuthNInfo = (ChipAuthenticationInfo)securityInfo;
        map.add(chipAuthNInfo);
        if (chipAuthNInfo.getKeyId() == null) {
          return map;
        }
      }
    }
    return map;
  }

  /**
   * Returns the mapping of key identifiers to public keys.
   * The key identifier may be -1 if there is only one key.
   *
   * @return the mapping of key identifiers to public keys
   *
   * @deprecated Clients should use {@link #getSecurityInfos()} and filter that collection
   */
  @Deprecated
  public List<ChipAuthenticationPublicKeyInfo> getChipAuthenticationPublicKeyInfos() {
    List<ChipAuthenticationPublicKeyInfo> publicKeys = new ArrayList<ChipAuthenticationPublicKeyInfo>();
    for (SecurityInfo securityInfo: securityInfos) {
      if (securityInfo instanceof ChipAuthenticationPublicKeyInfo) {
        publicKeys.add((ChipAuthenticationPublicKeyInfo)securityInfo);
      }
    }
    return publicKeys;
  }

  /**
   * Returns the Active Authentication security infos.
   *
   * @return the Active Authentication security infos
   *
   * @deprecated Clients should use {@link #getSecurityInfos()} and filter that collection
   */
  @Deprecated
  public List<ActiveAuthenticationInfo> getActiveAuthenticationInfos() {
    List<ActiveAuthenticationInfo> resultList = new ArrayList<ActiveAuthenticationInfo>();
    for (SecurityInfo securityInfo: securityInfos) {
      if (securityInfo instanceof ActiveAuthenticationInfo) {
        ActiveAuthenticationInfo activeAuthenticationInfo = (ActiveAuthenticationInfo)securityInfo;
        resultList.add(activeAuthenticationInfo);
      }
    }
    return resultList;
  }

  /**
   * Returns the security infos as an unordered collection.
   *
   * @return security infos
   */
  public Collection<SecurityInfo> getSecurityInfos() {
    return securityInfos;
  }

  @Override
  public String toString() {
    return "DG14File [" + securityInfos.toString() + "]";
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    }
    if (!(obj.getClass().equals(this.getClass()))) {
      return false;
    }

    DG14File other = (DG14File)obj;
    if (securityInfos == null) {
      return  other.securityInfos == null;
    }
    if (other.securityInfos == null) {
      return securityInfos == null;
    }

    return securityInfos.equals(other.securityInfos);
  }

  @Override
  public int hashCode() {
    return 5 * securityInfos.hashCode() + 41;
  }
}
