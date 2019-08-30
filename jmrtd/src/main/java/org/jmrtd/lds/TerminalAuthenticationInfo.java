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
 * $Id: TerminalAuthenticationInfo.java 1808 2019-03-07 21:32:19Z martijno $
 */

package org.jmrtd.lds;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;

/**
 * A concrete SecurityInfo structure that stores terminal authentication
 * info, see EAC 1.11 specification.
 *
 * This data structure provides detailed information on an implementation of Terminal Authentication.
 * <ul>
 * <li>The object identifier <code>protocol</code> SHALL identify the Terminal
 *     Authentication Protocol as the specific protocol may change over time.</li>
 * <li>The integer <code>version</code> SHALL identify the version of the protocol.
 *     Currently, versions 1 and 2 are supported.</li>
 * <li>The sequence <code>efCVCA</code> MAY be used to indicate a (short) file
 *     identifier of the file EF.CVCA. It MUST be used, if the default (short) file
 *     identifier is not used.</li>
 * </ul>
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1808 $
 */
public class TerminalAuthenticationInfo extends SecurityInfo {

  private static final long serialVersionUID = 6220506985707094044L;

  public static final int VERSION_1 = 1;
  private static final int VERSION_2 = 2;

  private String oid;
  private int version;

  /*
   * FIXME: This shouldn't be transient, as we want this part of the state to be (de)serialized.
   *
   * This contains just a file identifier, and possibly a short file identifier?
   * Why not short instead of ASN1Sequence? (In which case we can remove the transient.)
   *
   * Alternatively we could explicitly (de)serialize this in readObject/writeObject
   * (using BC's getEncoded()).
   */
  private transient ASN1Sequence efCVCA;

  /**
   * Constructs a new object.
   *
   * @param oid the id_TA identifier
   * @param version has to be 1 or 2
   * @param efCVCA the file ID information of the efCVCA file
   */
  TerminalAuthenticationInfo(String oid, int version, ASN1Sequence efCVCA) {
    this.oid = oid;
    this.version = version;
    this.efCVCA = efCVCA;
    checkFields();
  }

  /**
   * Constructs a new object.
   *
   * @param identifier the id_TA identifier
   * @param version has to be 1 or 2
   */
  TerminalAuthenticationInfo(String identifier, int version) {
    this(identifier, version, null);
  }

  /**
   * Constructs a terminal authentication info using id_TA identifier {@link #ID_TA}
   * and version {@value #VERSION_1}.
   */
  public TerminalAuthenticationInfo() {
    this(ID_TA, VERSION_1);
  }

  /**
   * Constructs a new Terminal Authentication info with the required
   * object identifier and version number 1, and file identifier and
   * short file identifier (possibly -1).
   *
   * @param fileId a file identifier reference to the efCVCA file
   * @param shortFileId short file id for the above file, -1 if none
   */
  public TerminalAuthenticationInfo(short fileId, byte shortFileId) {
    this(ID_TA, VERSION_1, constructEFCVCA(fileId, shortFileId));
  }

  /**
   * Returns the version. This will be 1 or 2.
   *
   * @return the version
   */
  public int getVersion() {
    return version;
  }

  /**
   * Returns a DER object with this SecurityInfo data (DER sequence).
   *
   * @return a DER object with this SecurityInfo data
   *
   * @deprecated this method will be removed from visible interface (because of dependency on BC API)
   */
  @Override
  @Deprecated
  public ASN1Primitive getDERObject() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new ASN1ObjectIdentifier(oid));
    v.add(new ASN1Integer(version));
    if (efCVCA != null) {
      v.add(efCVCA);
    }
    return new DLSequence(v);
  }

  /**
   * Returns the object identifier of this Terminal Authentication info.
   *
   * @return an object identifier
   */
  @Override
  public String getObjectIdentifier() {
    return oid;
  }

  /**
   * Returns the protocol object identifier as a human readable string.
   *
   * @return a string
   */
  @Override
  public String getProtocolOIDString() {
    return toProtocolOIDString(oid);
  }

  /**
   * Returns the efCVCA file identifier stored in this file, -1 if none.
   *
   * @return the efCVCA file identifier stored in this file
   */
  public int getFileId() {
    return getFID(efCVCA);
  }

  /**
   * Returns the efCVCA short file identifier stored in this file, -1 if none
   * or not present.
   *
   * @return the efCVCA short file identifier stored in this file
   */
  public byte getShortFileId() {
    return getSFI(efCVCA);
  }

  @Override
  public String toString() {
    return new StringBuilder()
        .append("TerminalAuthenticationInfo [")
        .append("protocol: ").append(toProtocolOIDString(oid)).append(", ")
        .append("version: ").append(version).append(", ")
        .append("fileID: ").append(getFileId()).append(", ")
        .append("shortFileID: ").append(getShortFileId())
        .append("]")
        .toString();
  }

  @Override
  public int hashCode() {
    return 123
        + 7 * (oid == null ? 0 : oid.hashCode())
        + 5 * version
        + 3 * (efCVCA == null ? 1 : efCVCA.hashCode());
  }

  @Override
  public boolean equals(Object other) {
    if (other == null) {
      return false;
    }
    if (other == this) {
      return true;
    }
    if (!TerminalAuthenticationInfo.class.equals(other.getClass())) {
      return false;
    }
    TerminalAuthenticationInfo otherTerminalAuthenticationInfo = (TerminalAuthenticationInfo) other;
    if (efCVCA == null && otherTerminalAuthenticationInfo.efCVCA != null) {
      return false;
    }
    if (efCVCA != null && otherTerminalAuthenticationInfo.efCVCA == null) {
      return false;
    }

    return getDERObject().equals(otherTerminalAuthenticationInfo.getDERObject());
  }

  /* ONLY NON-PUBLIC METHODS BELOW */

  /**
   * Checks whether the given object identifier identifies a
   * TerminalAuthenticationInfo structure.
   *
   * @param id
   *            object identifier
   * @return true if the match is positive
   */
  static boolean checkRequiredIdentifier(String id) {
    return ID_TA.equals(id);
  }

  /**
   * Checks the correctness of the data for this instance of {@code SecurityInfo}.
   */
  private void checkFields() {
    try {
      if (!checkRequiredIdentifier(oid)) {
        throw new IllegalArgumentException("Wrong identifier: " + oid);
      }
      if (version != VERSION_1 && version != VERSION_2) {
        throw new IllegalArgumentException("Wrong version. Was expecting " + VERSION_1 + " or " + VERSION_2
            + ", found " + version);
      }
      if (efCVCA != null) {
        DEROctetString fid = (DEROctetString)efCVCA.getObjectAt(0);
        if (fid.getOctets().length != 2) {
          throw new IllegalArgumentException("Malformed FID.");
        }
        if (efCVCA.size() == 2) {
          DEROctetString sfi = (DEROctetString)efCVCA.getObjectAt(1);
          if (sfi.getOctets().length != 1) {
            throw new IllegalArgumentException("Malformed SFI.");
          }
        }
      }
    } catch (Exception e) {
      throw new IllegalArgumentException("Malformed TerminalAuthenticationInfo", e);
    }
  }

  /**
   * Encodes the BC object representing a reference to a CVCA file.
   *
   * @param fid the file identifier
   * @param sfi the short file identifier
   *
   * @return an BC ASN1 sequence
   */
  private static ASN1Sequence constructEFCVCA(short fid, byte sfi) {
    if (sfi != -1) {
      return new DLSequence(new ASN1Encodable[] {
          new DEROctetString(new byte[] { (byte)((fid & 0xFF00) >> 8), (byte)(fid & 0xFF) }),
          new DEROctetString(new byte[] { (byte)(sfi & 0xFF) }) });
    } else {
      return new DLSequence(new ASN1Encodable[] {
          new DEROctetString(new byte[] { (byte)((fid & 0xFF00) >> 8), (byte)(fid & 0xFF) }) });
    }
  }

  /**
   * Returns the file identifier encoded in an BC ASN1 sequence.
   *
   * @param efCVCA the BC ASN1 sequence
   *
   * @return the file identifier
   */
  private static short getFID(ASN1Sequence efCVCA) {
    if (efCVCA == null) {
      return -1;
    }
    ASN1Sequence s = efCVCA;
    DEROctetString fid = (DEROctetString)s.getObjectAt(0);
    byte[] bytes = fid.getOctets();
    return (short)(((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF));
  }

  /**
   * Returns the short file identifier encoded in an BC ASN1 sequence.
   *
   * @param efCVCA the BC ASN1 sequence
   *
   * @return the short file identifier
   */
  private static byte getSFI(ASN1Sequence efCVCA) {
    if (efCVCA == null) {
      return -1;
    }
    if (efCVCA.size() != 2) {
      return -1;
    }
    return ((DEROctetString)efCVCA.getObjectAt(1)).getOctets()[0];
  }

  /**
   * Returns the ASN1 name for the given protocol object identifier.
   *
   * @param oid the protocol object identifier
   *
   * @return the ASN1 name if known, or the original object identifier if not
   */
  private String toProtocolOIDString(String oid) {
    if (ID_TA.equals(oid)) {
      return "id-TA";
    }
    if (ID_TA_RSA.equals(oid)) {
      return "id-TA-RSA";
    }
    if (ID_TA_RSA_V1_5_SHA_1.equals(oid)) {
      return "id-TA-RSA-v1-5-SHA-1";
    }
    if (ID_TA_RSA_V1_5_SHA_256.equals(oid)) {
      return "id-TA-RSA-v1-5-SHA-256";
    }
    if (ID_TA_RSA_PSS_SHA_1.equals(oid)) {
      return "id-TA-RSA-PSS-SHA-1";
    }
    if (ID_TA_RSA_PSS_SHA_256.equals(oid)) {
      return "id-TA-RSA-PSS-SHA-256";
    }
    if (ID_TA_ECDSA.equals(oid)) {
      return "id-TA-ECDSA";
    }
    if (ID_TA_ECDSA_SHA_1.equals(oid)) {
      return "id-TA-ECDSA-SHA-1";
    }
    if (ID_TA_ECDSA_SHA_224.equals(oid)) {
      return "id-TA-ECDSA-SHA-224";
    }
    if (ID_TA_ECDSA_SHA_256.equals(oid)) {
      return "id-TA-ECDSA-SHA-256";
    }

    return oid;
  }
}
