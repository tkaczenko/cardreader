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
 * $Id: DG15File.java 1808 2019-03-07 21:32:19Z martijno $
 */

package org.jmrtd.lds.icao;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.Util;
import org.jmrtd.lds.DataGroup;

/**
 * File structure for the EF_DG15 file.
 * Datagroup 15 contains the public key used in Active Authentication.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1808 $
 */
public class DG15File extends DataGroup {

  private static final long serialVersionUID = 3834304239673755744L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private static final String[] PUBLIC_KEY_ALGORITHMS = { "RSA", "EC" };

  private PublicKey publicKey;

  /**
   * Constructs a new file.
   *
   * @param publicKey the key to store in this file
   */
  public DG15File(PublicKey publicKey) {
    super(EF_DG15_TAG);
    this.publicKey = publicKey;
  }

  /**
   * Constructs a new file from binary representation.
   *
   * @param inputStream an input stream
   *
   * @throws IOException on error reading from input stream
   */
  public DG15File(InputStream inputStream) throws IOException {
    super(EF_DG15_TAG, inputStream);
  }

  @Override
  protected void readContent(InputStream inputStream) throws IOException {
    DataInputStream dataInputStream = inputStream instanceof DataInputStream ? (DataInputStream)inputStream : new DataInputStream(inputStream);
    try {
      byte[] value = new byte[getLength()];
      dataInputStream.readFully(value);

      publicKey = getPublicKey(value);
    } catch (GeneralSecurityException e) {
      LOGGER.log(Level.WARNING, "Unexpected exception while reading DG15 content", e);
    }
  }

  /**
   * Constructs a public key from the given key bytes.
   * Public keys of type {@code "RSA"} and {@code "EC"}
   * in X509 encoding are supported.
   *
   * @param keyBytes an X509 encoded public key
   *
   * @return a public object
   *
   * @throws GeneralSecurityException when the bytes cannot be interpreted as a public key
   */
  private static PublicKey getPublicKey(byte[] keyBytes) throws GeneralSecurityException {
    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(keyBytes);

    for (String algorithm: PUBLIC_KEY_ALGORITHMS) {
      try {
        return Util.getPublicKey(algorithm, pubKeySpec);
      } catch (InvalidKeySpecException ikse) {
        LOGGER.log(Level.FINE, "Ignore, try next algorithm", ikse);
      }
    }

    throw new InvalidAlgorithmParameterException();
  }

  @Override
  protected void writeContent(OutputStream out) throws IOException {
    out.write(publicKey.getEncoded());
  }

  /**
   * Returns the public key stored in this file.
   *
   * @return the public key
   */
  public PublicKey getPublicKey() {
    return publicKey;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    }
    if (obj.getClass() != this.getClass()) {
      return false;
    }

    DG15File other = (DG15File)obj;
    return publicKey.equals(other.publicKey);
  }

  @Override
  public int hashCode() {
    return 5 * publicKey.hashCode() + 61;
  }

  @Override
  public String toString() {
    return "DG15File [" + Util.getDetailedPublicKeyAlgorithm(publicKey) + "]";
  }
}
