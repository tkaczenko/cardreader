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
 * $Id: CertificateUtil.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;

/**
 * Certificate utilities for testing.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1813 $
 */
public class CertificateUtil {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /**
   * Prevents instantiation.
   */
  private CertificateUtil() {
  }

  /**
   * Generates a certificate.
   *
   * @param issuer the issuer DN as a comma-separated list
   * @param subject the subject DN as a comma-separated list
   * @param dateOfIssuing the date of issuing
   * @param dateOfExpiry the date of expiry
   * @param subjecPublicKey the subject's public key
   * @param issuerPrivateKey the issuer's private key
   * @param signatureAlgorithm the signature algorithm to use in Java mnemonic notation
   *
   * @return the generated certificate
   */
  public static X509Certificate createCertificate(String issuer, String subject, Date dateOfIssuing, Date dateOfExpiry,
      PublicKey subjectPublicKey, PrivateKey issuerPrivateKey, String signatureAlgorithm) {
    try {
      X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(new X500Name(issuer), new BigInteger("1"), dateOfIssuing, dateOfExpiry, new X500Name(subject), SubjectPublicKeyInfo.getInstance(subjectPublicKey.getEncoded()));
      byte[] certBytes = certBuilder.build(new JCESigner(issuerPrivateKey, signatureAlgorithm)).getEncoded();
      CertificateFactory certificateFactory = null;
      certificateFactory = CertificateFactory.getInstance("X.509");
      return (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));
    } catch (Exception  e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * A content signer implementation.
   */
  private static class JCESigner implements ContentSigner {

    private static final List<String> SUPPORTED_ALGORITHMS = Arrays.asList(new String[] { "SHA256withRSA", "SHA256withECDSA" });
    private static final AlgorithmIdentifier PKCS1_SHA256_WITH_RSA_OID = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"));
    private static final AlgorithmIdentifier X9_SHA256_WITH_ECDSA_OID = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"));

    private Signature signature;
    private ByteArrayOutputStream outputStream;

    public JCESigner(PrivateKey privateKey, String signatureAlgorithm) {
      if (!SUPPORTED_ALGORITHMS.contains(signatureAlgorithm)) {
        throw new IllegalArgumentException("Signature algorithm \"" + signatureAlgorithm + "\" not yet supported");
      }
      try {
        this.outputStream = new ByteArrayOutputStream();
        this.signature = Signature.getInstance(signatureAlgorithm);
        this.signature.initSign(privateKey);
      } catch (GeneralSecurityException gse) {
        throw new IllegalArgumentException(gse);
      }
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
      if (signature.getAlgorithm().equals("SHA256withRSA")) {
        return PKCS1_SHA256_WITH_RSA_OID;
      } else if (signature.getAlgorithm().equals("SHA256withECDSA")) {
        return X9_SHA256_WITH_ECDSA_OID;
      } else {
        return null;
      }
    }

    public OutputStream getOutputStream() {
      return outputStream;
    }

    public byte[] getSignature() {
      try {
        signature.update(outputStream.toByteArray());
        return signature.sign();
      } catch (GeneralSecurityException gse) {
        LOGGER.log(Level.WARNING, "Exception", gse);
        return null;
      }
    }
  }
}
