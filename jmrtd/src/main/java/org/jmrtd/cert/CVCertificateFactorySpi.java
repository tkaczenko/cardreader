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
 * $Id: CVCertificateFactorySpi.java 1751 2018-01-15 15:35:45Z martijno $
 */

package org.jmrtd.cert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactorySpi;
import java.util.Collection;

import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;

import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVOutputStream;

/**
 * Card verifiable certificate factory.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1751 $
 *
 * @see CardVerifiableCertificate
 */
public class CVCertificateFactorySpi extends CertificateFactorySpi {

  private static final int CV_CERTIFICATE_TAG = 0x7F21;

  /**
   * Generates the certificate based on an input source.
   *
   * @param inputStream the input source
   *
   * @throws CertificateException on parsing errors
   */
  @Override
  public Certificate engineGenerateCertificate(InputStream inputStream) throws CertificateException {
    try {
      /* Read certificate as byte[] */
      TLVInputStream tlvIn = new TLVInputStream(inputStream);
      int tag = tlvIn.readTag();
      if (tag != CV_CERTIFICATE_TAG) {
        throw new CertificateException("Expected CV_CERTIFICATE_TAG, found " + Integer.toHexString(tag));
      }
      /* int length = */ tlvIn.readLength();
      byte[] value = tlvIn.readValue();

      ByteArrayOutputStream out = new ByteArrayOutputStream();
      TLVOutputStream tlvOut = new TLVOutputStream(out);
      tlvOut.writeTag(CV_CERTIFICATE_TAG);
      tlvOut.writeValue(value);
      tlvOut.close();
      CVCObject parsedObject = CertificateParser.parseCertificate(out.toByteArray());
      return new CardVerifiableCertificate((org.ejbca.cvc.CVCertificate)parsedObject);
    } catch (IOException ioe) {
      throw new CertificateException(ioe);
    } catch (ConstructionException ce) {
      throw new CertificateException(ce);
    } catch (ParseException pe) {
      throw new CertificateException(pe);
    }
  }

  /**
   * Not implemented.
   *
   * @param inputStream input stream
   */
  @Override
  public CRL engineGenerateCRL(InputStream inputStream) throws CRLException {
    return null; // TODO
  }

  /**
   * Not implemented.
   *
   * @param inputStream input stream
   */
  @Override
  public Collection<? extends CRL> engineGenerateCRLs(InputStream inputStream) throws CRLException {
    return null; // TODO
  }

  @Override
  public Collection<? extends Certificate> engineGenerateCertificates(InputStream in) throws CertificateException {
    return null; // TODO
  }
}
