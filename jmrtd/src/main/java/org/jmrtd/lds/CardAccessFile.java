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
 * $Id: CardAccessFile.java 1808 2019-03-07 21:32:19Z martijno $
 */

package org.jmrtd.lds;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DLSet;

/**
 * Card access file stores a set of SecurityInfos for PACE.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1808 $
 *
 * @since 0.5.1
 */
public class CardAccessFile implements Serializable {

  private static final long serialVersionUID = -3536507558193769951L;

  /** The security infos that make up this file. */
  private Set<SecurityInfo> securityInfos;

  /**
   * Constructs a new file from the provided data.
   *
   * @param securityInfos a non-empty list of security infos
   */
  public CardAccessFile(Collection<SecurityInfo> securityInfos) {
    if (securityInfos == null) {
      throw new IllegalArgumentException("Null securityInfos");
    }
    this.securityInfos = new HashSet<SecurityInfo>(securityInfos);
  }

  /**
   * Constructs a new file from the data in an input stream.
   *
   * @param inputStream the input stream to parse the data from
   *
   * @throws IOException on error reading input stream
   */
  public CardAccessFile(InputStream inputStream) throws IOException {
    readContent(inputStream);
  }

  /**
   * Reads the contents as a card access file from a stream.
   *
   * @param inputStream the stream to read from
   *
   * @throws IOException on error reading from the stream
   */
  protected void readContent(InputStream inputStream) throws IOException {
    securityInfos = new HashSet<SecurityInfo>();
    ASN1InputStream asn1In = new ASN1InputStream(inputStream);
    ASN1Set set = (ASN1Set)asn1In.readObject();
    for (int i = 0; i < set.size(); i++) {
      ASN1Primitive object = set.getObjectAt(i).toASN1Primitive();
      SecurityInfo securityInfo = SecurityInfo.getInstance(object);
      if (securityInfo == null) {
        /* NOTE: skipping this unsupported SecurityInfo */
        continue;
      }
      securityInfos.add(securityInfo);
    }
  }

  /* FIXME: rewrite (using writeObject instead of getDERObject) to remove interface dependency on BC. */
  /**
   * Writes the contents of this file to a stream.
   *
   * @param outputStream the stream to write to
   *
   * @throws IOException on error writing to the stream
   */
  protected void writeContent(OutputStream outputStream) throws IOException {
    ASN1EncodableVector vector = new ASN1EncodableVector();
    for (SecurityInfo securityInfo: securityInfos) {
      vector.add(securityInfo.getDERObject());
    }
    ASN1Set derSet = new DLSet(vector);
    outputStream.write(derSet.getEncoded(ASN1Encoding.DER));
  }

  /**
   * Returns the security infos as an unordered collection.
   *
   * @return security infos
   */
  public Collection<SecurityInfo> getSecurityInfos() {
    return Collections.unmodifiableCollection(securityInfos);
  }

  /**
   * Returns the signature algorithm object identifier.
   *
   * @return signature algorithm OID
   */
  @Override
  public String toString() {
    return new StringBuilder()
        .append("CardAccessFile [")
        .append(securityInfos.toString())
        .append("]").toString();
  }

  /**
   * Tests equality with respect to another object.
   *
   * @param otherObj another object
   *
   * @return whether this object equals the other object
   */
  @Override
  public boolean equals(Object otherObj) {
    if (otherObj == null) {
      return false;
    }

    if (!(otherObj.getClass().equals(this.getClass()))) {
      return false;
    }

    CardAccessFile other = (CardAccessFile)otherObj;
    if (securityInfos == null) {
      return  other.securityInfos == null;
    }
    if (other.securityInfos == null) {
      return securityInfos == null;
    }

    return securityInfos.equals(other.securityInfos);
  }

  /**
   * Returns a hash code of this object.
   *
   * @return the hash code
   */
  @Override
  public int hashCode() {
    return 7 * securityInfos.hashCode() + 61;
  }
}
