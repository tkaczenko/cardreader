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
 * $Id: SignedDataUtil.java 1812 2019-05-27 14:36:59Z martijno $
 */

package org.jmrtd.lds;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.jmrtd.Util;

/**
 * Utility class for helping with CMS SignedData in security object document and
 * card security file.
 *
 * This hopefully abstracts some of the BC dependencies away.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1812 $
 */
public final class SignedDataUtil {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /** SignedData related object identifier. */
  public static final String RFC_3369_SIGNED_DATA_OID = "1.2.840.113549.1.7.2"; /* id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 } */

  /** SignedData related object identifier. */
  public static final String RFC_3369_CONTENT_TYPE_OID = "1.2.840.113549.1.9.3";

  /** SignedData related object identifier. */
  public static final String RFC_3369_MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4";

  /** SignedData related object identifier. */
  public static final String PKCS1_RSA_OID = "1.2.840.113549.1.1.1";

  /** SignedData related object identifier. */
  public static final String PKCS1_MD2_WITH_RSA_OID = "1.2.840.113549.1.1.2";

  /** SignedData related object identifier. */
  public static final String PKCS1_MD4_WITH_RSA_OID = "1.2.840.113549.1.1.3";

  /** SignedData related object identifier. */
  public static final String PKCS1_MD5_WITH_RSA_OID = "1.2.840.113549.1.1.4";

  /** SignedData related object identifier. */
  public static final String PKCS1_SHA1_WITH_RSA_OID = "1.2.840.113549.1.1.5";

  /** SignedData related object identifier. */
  public static final String PKCS1_MGF1 = "1.2.840.113549.1.1.8";

  /** SignedData related object identifier. */
  public static final String PKCS1_RSASSA_PSS_OID = "1.2.840.113549.1.1.10";

  /** SignedData related object identifier. */
  public static final String PKCS1_SHA256_WITH_RSA_OID = "1.2.840.113549.1.1.11";

  /** SignedData related object identifier. */
  public static final String PKCS1_SHA384_WITH_RSA_OID = "1.2.840.113549.1.1.12";

  /** SignedData related object identifier. */
  public static final String PKCS1_SHA512_WITH_RSA_OID = "1.2.840.113549.1.1.13";

  /** SignedData related object identifier. */
  public static final String PKCS1_SHA224_WITH_RSA_OID = "1.2.840.113549.1.1.14";

  /** SignedData related object identifier. */
  public static final String X9_SHA1_WITH_ECDSA_OID = "1.2.840.10045.4.1";

  /** SignedData related object identifier. */
  public static final String X9_SHA224_WITH_ECDSA_OID = "1.2.840.10045.4.3.1";

  /** SignedData related object identifier. */
  public static final String X9_SHA256_WITH_ECDSA_OID = "1.2.840.10045.4.3.2";

  /** SignedData related object identifier. */
  public static final String X9_SHA384_WITH_ECDSA_OID = "1.2.840.10045.4.3.3";

  /** SignedData related object identifier. */
  public static final String X9_SHA512_WITH_ECDSA_OID = "1.2.840.10045.4.3.4";

  /** SignedData related object identifier. */
  public static final String IEEE_P1363_SHA1_OID = "1.3.14.3.2.26";

  /**
   * Prevents instantiation.
   */
  private SignedDataUtil() {
  }

  /**
   * Reads a signed data structure from a stream.
   *
   * @param inputStream the stream to read from
   *
   * @return the signed data structure
   *
   * @throws IOException on error reading from the stream
   */
  public static SignedData readSignedData(InputStream inputStream) throws IOException {
    ASN1InputStream asn1InputStream = new ASN1InputStream(inputStream);
    ASN1Sequence sequence = (ASN1Sequence)asn1InputStream.readObject();

    if (sequence.size() != 2) {
      throw new IOException("Was expecting a DER sequence of length 2, found a DER sequence of length " + sequence.size());
    }

    String contentTypeOID = ((ASN1ObjectIdentifier)sequence.getObjectAt(0)).getId();
    if (!RFC_3369_SIGNED_DATA_OID.equals(contentTypeOID)) {
      throw new IOException("Was expecting signed-data content type OID (" + RFC_3369_SIGNED_DATA_OID + "), found " + contentTypeOID);
    }

    ASN1Primitive asn1SequenceWithSignedData = getObjectFromTaggedObject(sequence.getObjectAt(1));

    if (!(asn1SequenceWithSignedData instanceof ASN1Sequence)) {
      throw new IOException("Was expecting an ASN.1 sequence as content");
    }

    return SignedData.getInstance(asn1SequenceWithSignedData);
  }

  /**
   * Writes a signed data structure to a stream.
   *
   * @param signedData the signed data to write
   * @param outputStream the stream to write to
   *
   * @throws IOException on error writing to the stream
   */
  public static void writeData(SignedData signedData, OutputStream outputStream) throws IOException {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new ASN1ObjectIdentifier(RFC_3369_SIGNED_DATA_OID));
    v.add(new DERTaggedObject(0, signedData));
    ASN1Sequence fileContentsObject = new DLSequence(v);
    byte[] fileContentsBytes = fileContentsObject.getEncoded(ASN1Encoding.DER);
    outputStream.write(fileContentsBytes);
  }

  /**
   * Extracts the content from a signed data structure.
   *
   * @param signedData the signed data
   *
   * @return the contents of the e-content in the signed data structure
   */
  public static ASN1Primitive getContent(SignedData signedData) {
    ContentInfo encapContentInfo = signedData.getEncapContentInfo();

    DEROctetString eContent = (DEROctetString)encapContentInfo.getContent();

    ASN1InputStream inputStream = null;
    try {
      inputStream = new ASN1InputStream(new ByteArrayInputStream(eContent.getOctets()));
      return inputStream.readObject();
    } catch (IOException ioe) {
      LOGGER.log(Level.WARNING, "Unexpected exception", ioe);
    } finally {
      if (inputStream != null) {
        try {
          inputStream.close();
        } catch (IOException ioe) {
          LOGGER.log(Level.FINE, "Exception closing input stream", ioe);
          /* At least we tried... */
        }
      }
    }

    return null;
  }

  /**
   * Removes the tag from a tagged object.
   *
   * @param asn1Encodable the encoded tagged object
   *
   * @return the object
   *
   * @throws IOException if the input is not a tagged object or the tagNo is not 0
   */
  public static ASN1Primitive getObjectFromTaggedObject(ASN1Encodable asn1Encodable) throws IOException {
    if (!(asn1Encodable instanceof ASN1TaggedObject)) {
      throw new IOException("Was expecting an ASN1TaggedObject, found " + asn1Encodable.getClass().getCanonicalName());
    }

    ASN1TaggedObject asn1TaggedObject = (ASN1TaggedObject)asn1Encodable;

    int tagNo = asn1TaggedObject.getTagNo();
    if (tagNo != 0) {
      throw new IOException("Was expecting tag 0, found " + Integer.toHexString(tagNo));
    }

    return asn1TaggedObject.getObject();
  }

  /**
   * Returns the digest algirithm used in the signer info in a signed data structure.
   *
   * @param signedData the signed data structure
   *
   * @return the digest algorithm
   */
  public static String getSignerInfoDigestAlgorithm(SignedData signedData) {
    try {
      SignerInfo signerInfo = getSignerInfo(signedData);
      String digestAlgOID = signerInfo.getDigestAlgorithm().getAlgorithm().getId();
      return lookupMnemonicByOID(digestAlgOID);
    } catch (NoSuchAlgorithmException nsae) {
      LOGGER.log(Level.WARNING, "No such algorithm" + nsae);
      return null;
    }
  }

  /**
   * Returns the parameters of the digest encryption (signature) algorithm
   * used in the given signed data object.
   * For instance for {@code "RSASSA/PSS"} this includes the hash algorithm
   * and the salt length.
   *
   * @param signedData the signed data object
   *
   * @return the algorithm parameters
   */
  public static AlgorithmParameterSpec getDigestEncryptionAlgorithmParams(SignedData signedData) {
    try {
      SignerInfo signerInfo = getSignerInfo(signedData);
      AlgorithmIdentifier digestEncryptionAlgorithm = signerInfo.getDigestEncryptionAlgorithm();
      ASN1Encodable params = digestEncryptionAlgorithm.getParameters();

      String digestEncryptionAlgorithmOID = digestEncryptionAlgorithm.getAlgorithm().getId();
      if (PKCS1_RSASSA_PSS_OID.equals(digestEncryptionAlgorithmOID)) {
        RSASSAPSSparams rsaSSAParams = RSASSAPSSparams.getInstance(params);
        return toAlgorithmParameterSpec(rsaSSAParams);
      }
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
    }

    return null;
  }

  /**
   * Returns the signature algorithm used in the given signed data structure.
   *
   * @param signedData the signed data structure
   *
   * @return a JCE mnemonic algorithm string
   */
  public static String getDigestEncryptionAlgorithm(SignedData signedData) {
    try {
      SignerInfo signerInfo = getSignerInfo(signedData);
      String digestEncryptionAlgorithmOID = signerInfo.getDigestEncryptionAlgorithm().getAlgorithm().getId();
      if (digestEncryptionAlgorithmOID == null) {
        LOGGER.warning("Could not determine digest encryption algorithm OID");
        return null;
      }
      return lookupMnemonicByOID(digestEncryptionAlgorithmOID);
    } catch (NoSuchAlgorithmException nsae) {
      LOGGER.log(Level.WARNING, "No such algorithm", nsae);
      return null;
    }
  }

  /**
   * Returns the contents of the signed data over which the
   * signature is to be computed.
   *
   * See RFC 3369, Cryptographic Message Syntax, August 2002,
   * Section 5.4 for details.
   *
   * FIXME: Maybe throw an exception instead of issuing warnings
   * on logger if signed attributes do not check out.
   *
   * @param signedData the signed data
   *
   * @return the contents of the security object over which the
   *         signature is to be computed
   *
   * @throws SignatureException if the contents do not check out
   */
  public static byte[] getEContent(SignedData signedData) throws SignatureException{
    SignerInfo signerInfo = getSignerInfo(signedData);
    ASN1Set signedAttributesSet = signerInfo.getAuthenticatedAttributes();

    ContentInfo contentInfo = signedData.getEncapContentInfo();
    byte[] contentBytes = ((DEROctetString)contentInfo.getContent()).getOctets();

    if (signedAttributesSet.size() == 0) {
      /* Signed attributes absent, return content to be signed... */
      return contentBytes;
    }

    /* Signed attributes present (i.e. a structure containing a hash of the content), return that structure to be signed... */
    /* This option is taken by ICAO passports. */
    byte[] attributesBytes = null;
    String digAlg = signerInfo.getDigestAlgorithm().getAlgorithm().getId();

    try {
      attributesBytes = signedAttributesSet.getEncoded(ASN1Encoding.DER);

      checkEContent(getAttributes(signedAttributesSet), digAlg, contentBytes);

    } catch (NoSuchAlgorithmException nsae) {
      LOGGER.log(Level.WARNING, "Error checking signedAttributes in eContent! No such algorithm: \"" + digAlg, nsae);
    } catch (IOException ioe) {
      LOGGER.log(Level.WARNING, "Error getting signedAttributes", ioe);
    }

    return attributesBytes;
  }

  /**
   * Returns the stored signature of the security object.
   *
   * @param signedData the signed data
   *
   * @return the signature
   */
  public static byte[] getEncryptedDigest(SignedData signedData) {
    SignerInfo signerInfo = getSignerInfo(signedData);
    return signerInfo.getEncryptedDigest().getOctets();
  }

  /**
   * Returns the issuer and serial number stored in the given signed data structure.
   *
   * @param signedData the signed data structure
   *
   * @return the issuer and serial number
   */
  public static IssuerAndSerialNumber getIssuerAndSerialNumber(SignedData signedData) {
    SignerInfo signerInfo = getSignerInfo(signedData);
    SignerIdentifier signerIdentifier = signerInfo.getSID();
    ASN1Encodable signerIdentifierId = signerIdentifier.getId();
    if (!(signerIdentifierId instanceof ASN1Sequence || signerIdentifierId instanceof IssuerAndSerialNumber)) {
      /* NOTE: DE MasterList appears to use DER octet string here. */
      return null;
    }

    IssuerAndSerialNumber issuerAndSerialNumber = IssuerAndSerialNumber.getInstance(signerIdentifierId);
    X500Name issuer = issuerAndSerialNumber.getName();
    BigInteger serialNumber = issuerAndSerialNumber.getSerialNumber().getValue();
    return new IssuerAndSerialNumber(issuer, serialNumber);
  }

  /**
   * Reads any objects in the given ASN1 octet string (as an ASN1 input stream).
   *
   * @param octetString the octet string
   *
   * @return a list of objects read
   */
  public static List<ASN1Primitive> getObjectsFromOctetString(ASN1OctetString octetString) {
    List<ASN1Primitive> result = new ArrayList<ASN1Primitive>();
    byte[] octets = octetString.getOctets();
    ASN1InputStream derInputStream = new ASN1InputStream(new ByteArrayInputStream(octets));
    try {
      while (true) {
        ASN1Primitive derObject = derInputStream.readObject();
        if (derObject == null) {
          break;
        }
        result.add(derObject);
      }
      derInputStream.close();
    } catch (IOException ioe) {
      LOGGER.log(Level.WARNING, "Exception", ioe);
    }

    return result;
  }

  /**
   * Extracts the list of embedded certificates from a signed data object.
   *
   * @param signedData the signed data object
   *
   * @return the list of certificates
   */
  public static List<X509Certificate> getCertificates(SignedData signedData) {
    ASN1Set encodedCertificates = signedData.getCertificates();
    int certificateCount = encodedCertificates == null ? 0 : encodedCertificates.size();

    List<X509Certificate> result = new ArrayList<X509Certificate>(certificateCount);
    if (certificateCount <= 0) {
      return result;
    }

    for (int i = 0; i < certificateCount; i++) {
      try {
        org.bouncycastle.asn1.x509.Certificate certAsASN1Object = org.bouncycastle.asn1.x509.Certificate.getInstance(encodedCertificates.getObjectAt(i));
        result.add(decodeCertificate(certAsASN1Object));
      } catch (Exception e) {
        LOGGER.log(Level.WARNING, "Exception in decoding certificate", e);
      }
    }

    return result;
  }

  /**
   * Decodes an ASN1 encoded BC certificate object to a JCA certificate object.
   *
   * @param certAsASN1Object the ASN1 object
   *
   * @return an X509 certificate
   *
   * @throws IOException on error decoding the DER structure, never happens
   * @throws GeneralSecurityException on error decoding
   */
  public static X509Certificate decodeCertificate(org.bouncycastle.asn1.x509.Certificate certAsASN1Object) throws IOException, GeneralSecurityException {
    byte[] certSpec = certAsASN1Object.getEncoded(ASN1Encoding.DER);
    /*
     * NOTE: We explicitly prefer Bouncy Castle here. The default Sun provider claims to support all X509 encoded
     * certificates but cannot handle named EC curves
     * for EC public keys.
     */
    CertificateFactory factory = CertificateFactory.getInstance("X.509", Util.getBouncyCastleProvider());
    return (X509Certificate)factory.generateCertificate(new ByteArrayInputStream(certSpec));
  }

  /**
   * Creates a signed data structure, for inclusion in a security object.
   *
   * @param digestAlgorithm the digest algorithm
   * @param digestEncryptionAlgorithm the signature algorithm
   * @param contentTypeOID the object identifier
   * @param contentInfo the content info
   * @param encryptedDigest the signature bytes
   * @param docSigningCertificate the document signer certificate
   *
   * @return the signed data structure
   *
   * @throws GeneralSecurityException on error
   */
  public static SignedData createSignedData(String digestAlgorithm, String digestEncryptionAlgorithm,
      String contentTypeOID, ContentInfo contentInfo, byte[] encryptedDigest,
      X509Certificate docSigningCertificate) throws GeneralSecurityException {
    ASN1Set digestAlgorithmsSet = createSingletonSet(createDigestAlgorithms(digestAlgorithm));
    ASN1Set certificates =  createSingletonSet(createCertificate(docSigningCertificate));
    ASN1Set crls = null;
    ASN1Set signerInfos = createSingletonSet(createSignerInfo(digestAlgorithm, digestEncryptionAlgorithm, contentTypeOID, contentInfo, encryptedDigest, docSigningCertificate).toASN1Primitive());
    return new SignedData(digestAlgorithmsSet, contentInfo, certificates, crls, signerInfos);
  }

//  /**
//   * Creates a signer info structures.
//   *
//   * @param digestAlgorithm the digest algorithm
//   * @param digestEncryptionAlgorithm the signature algorithm
//   * @param contentTypeOID the object identifier
//   * @param contentInfo the content info
//   * @param encryptedDigest the signature bytes
//   * @param docSigningCertificate the document signer certificate
//   *
//   * @return the signer info structure
//   *
//   * @throws GeneralSecurityException on error
//   */
//  public static SignerInfo createSignerInfo(String digestAlgorithm,
//      String digestEncryptionAlgorithm, String contentTypeOID, ContentInfo contentInfo,
//      byte[] encryptedDigest, X509Certificate docSigningCertificate) throws GeneralSecurityException {
//
//    if (encryptedDigest == null) {
//      throw new IllegalArgumentException("Encrypted digest cannot be null");
//    }
//
//    /* Get the issuer name (CN, O, OU, C) from the cert and put it in a SignerIdentifier struct. */
//    X500Principal docSignerPrincipal = docSigningCertificate.getIssuerX500Principal();
//    X500Name docSignerName = new X500Name(docSignerPrincipal.getName(X500Principal.RFC2253));
//    BigInteger serial = docSigningCertificate.getSerialNumber();
//    SignerIdentifier sid = new SignerIdentifier(new IssuerAndSerialNumber(docSignerName, serial));
//
//    AlgorithmIdentifier digestAlgorithmObject = new AlgorithmIdentifier(new ASN1ObjectIdentifier(lookupOIDByMnemonic(digestAlgorithm)));
//    AlgorithmIdentifier digestEncryptionAlgorithmObject = new AlgorithmIdentifier(new ASN1ObjectIdentifier(lookupOIDByMnemonic(digestEncryptionAlgorithm)));
//
//    ASN1Set authenticatedAttributes = createAuthenticatedAttributes(digestAlgorithm, contentTypeOID, contentInfo); // struct containing the hash of content
//    ASN1OctetString encryptedDigestObject = new DEROctetString(encryptedDigest); // this is the signature
//    ASN1Set unAuthenticatedAttributes = null; // should be empty set?
//
//    return new SignerInfo(sid, digestAlgorithmObject, authenticatedAttributes, digestEncryptionAlgorithmObject, encryptedDigestObject, unAuthenticatedAttributes);
//  }

  /**
   * Creates a signer info structures.
   *
   * @param digestAlgorithm the digest algorithm
   * @param digestEncryptionAlgorithm the signature algorithm
   * @param contentTypeOID the object identifier
   * @param contentInfo the content info
   * @param encryptedDigest the signature bytes
   * @param docSigningCertificate the document signer certificate
   *
   * @return the signer info structure
   *
   * @throws GeneralSecurityException on error
   */
  public static SignerInfo createSignerInfo(String digestAlgorithm,
      String digestEncryptionAlgorithm, String contentTypeOID, ContentInfo contentInfo,
      byte[] encryptedDigest, X509Certificate docSigningCertificate) throws GeneralSecurityException {

    if (encryptedDigest == null) {
      throw new IllegalArgumentException("Encrypted digest cannot be null");
    }

    /* Get the issuer name (CN, O, OU, C) from the cert and put it in a SignerIdentifier struct. */
    Certificate bcCertificate = Certificate.getInstance(docSigningCertificate.getEncoded());
    X500Name docSignerName = bcCertificate.getIssuer();
    BigInteger serial = docSigningCertificate.getSerialNumber();
    SignerIdentifier sid = new SignerIdentifier(new IssuerAndSerialNumber(docSignerName, serial));

    AlgorithmIdentifier digestAlgorithmObject = new AlgorithmIdentifier(new ASN1ObjectIdentifier(lookupOIDByMnemonic(digestAlgorithm)));
    AlgorithmIdentifier digestEncryptionAlgorithmObject = new AlgorithmIdentifier(new ASN1ObjectIdentifier(lookupOIDByMnemonic(digestEncryptionAlgorithm)));

    ASN1Set authenticatedAttributes = createAuthenticatedAttributes(digestAlgorithm, contentTypeOID, contentInfo); // struct containing the hash of content
    ASN1OctetString encryptedDigestObject = new DEROctetString(encryptedDigest); // this is the signature
    ASN1Set unAuthenticatedAttributes = null; // should be empty set?

    return new SignerInfo(sid, digestAlgorithmObject, authenticatedAttributes, digestEncryptionAlgorithmObject, encryptedDigestObject, unAuthenticatedAttributes);
  }

  /**
   * Creates the authenticated attributes to be signed.
   *
   * @param digestAlgorithm the digest algorithm
   * @param contentTypeOID the object identifier
   * @param contentInfo the content info to digest
   *
   * @return authenticated attributes to be signed
   *
   * @throws GeneralSecurityException on error
   */
  public static ASN1Set createAuthenticatedAttributes(String digestAlgorithm, String contentTypeOID, ContentInfo contentInfo) throws GeneralSecurityException {
    /* Check bug found by Paulo Assumpco. */
    if ("SHA256".equals(digestAlgorithm)) {
      digestAlgorithm = "SHA-256";
    }
    MessageDigest dig = Util.getMessageDigest(digestAlgorithm);
    byte[] contentBytes = ((DEROctetString)contentInfo.getContent()).getOctets();
    byte[] digestedContentBytes = dig.digest(contentBytes);
    ASN1OctetString digestedContent = new DEROctetString(digestedContentBytes);
    Attribute contentTypeAttribute = new Attribute(new ASN1ObjectIdentifier(RFC_3369_CONTENT_TYPE_OID), createSingletonSet(new ASN1ObjectIdentifier(contentTypeOID)));
    Attribute messageDigestAttribute = new Attribute(new ASN1ObjectIdentifier(RFC_3369_MESSAGE_DIGEST_OID), createSingletonSet(digestedContent));
    ASN1Object[] result = { contentTypeAttribute.toASN1Primitive(), messageDigestAttribute.toASN1Primitive() };
    return new DLSet(result);
  }

  /**
   * Encodes the given JCE mnemonic digest algorithm as an BC ASN1 sequence.
   *
   * @param digestAlgorithm the JCE mnemonic digest algorithm
   *
   * @return the encoded digest algorithm
   *
   * @throws NoSuchAlgorithmException when the digest algorithm is not known
   */
  public static ASN1Sequence createDigestAlgorithms(String digestAlgorithm) throws NoSuchAlgorithmException {
    ASN1ObjectIdentifier algorithmIdentifier = new ASN1ObjectIdentifier(lookupOIDByMnemonic(digestAlgorithm));
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(algorithmIdentifier);
    return new DLSequence(v);
  }

  /**
   * Encodes an X509 certificate as a BC ASN1 sequence.
   *
   * @param certificate a certificate
   *
   * @return a BC ASN1 sequence with the encoded certificate
   *
   * @throws CertificateException on error
   */
  public static ASN1Sequence createCertificate(X509Certificate certificate) throws CertificateException {
    if (certificate == null) {
      throw new IllegalArgumentException("Cannot encode null certificate");
    }

    try {
      byte[] certSpec = certificate.getEncoded();
      ASN1InputStream asn1In = new ASN1InputStream(certSpec);
      try {
        return (ASN1Sequence)asn1In.readObject();
      } finally {
        try {
          asn1In.close();
        } catch (IOException ioe) {
          LOGGER.log(Level.FINE, "Error closing stream", ioe);
        }
      }
    } catch (IOException ioe) {
      throw new CertificateException("Could not construct certificate byte stream", ioe);
    }
  }

  /**
   * Signs the (authenticated attributes derived from the given) data.
   *
   * @param digestAlgorithm the digest algorithm
   * @param digestEncryptionAlgorithm the signature algorithm
   * @param contentTypeOID the object identifier
   * @param contentInfo the content info
   * @param privateKey the private key to use for signing
   * @param provider the preferred provider to use
   *
   * @return the signed data
   */
  public static byte[] signData(String digestAlgorithm, String digestEncryptionAlgorithm, String contentTypeOID, ContentInfo contentInfo, PrivateKey privateKey, String provider) {
    byte[] encryptedDigest = null;
    try {
      byte[] dataToBeSigned = createAuthenticatedAttributes(digestAlgorithm, contentTypeOID, contentInfo).getEncoded(ASN1Encoding.DER);
      Signature s = null;
      if (provider != null) {
        s = Signature.getInstance(digestEncryptionAlgorithm, provider);
      } else {
        s = Signature.getInstance(digestEncryptionAlgorithm);
      }
      s.initSign(privateKey);
      s.update(dataToBeSigned);
      encryptedDigest = s.sign();
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e) ;
      return null;
    }
    return encryptedDigest;
  }

  /**
   * Returns the common mnemonic string (such as "SHA1", "SHA256withRSA") given an OID.
   *
   * @param oid an object identifier
   *
   * @return a mnemonic string
   *
   * @throws NoSuchAlgorithmException if the provided OID is not yet supported
   */
  public static String lookupMnemonicByOID(String oid) throws NoSuchAlgorithmException {
    if (oid == null) {
      return null;
    }
    if (oid.equals(X509ObjectIdentifiers.organization.getId())) {
      return "O";
    }
    if (oid.equals(X509ObjectIdentifiers.organizationalUnitName.getId())) {
      return "OU";
    }
    if (oid.equals(X509ObjectIdentifiers.commonName.getId())) {
      return "CN";
    }
    if (oid.equals(X509ObjectIdentifiers.countryName.getId())) {
      return "C";
    }
    if (oid.equals(X509ObjectIdentifiers.stateOrProvinceName.getId())) {
      return "ST";
    }
    if (oid.equals(X509ObjectIdentifiers.localityName.getId())) {
      return "L";
    }
    if (oid.equals(X509ObjectIdentifiers.id_SHA1.getId())) {
      return "SHA-1";
    }
    if (oid.equals(NISTObjectIdentifiers.id_sha224.getId())) {
      return "SHA-224";
    }
    if (oid.equals(NISTObjectIdentifiers.id_sha256.getId())) {
      return "SHA-256";
    }
    if (oid.equals(NISTObjectIdentifiers.id_sha384.getId())) {
      return "SHA-384";
    }
    if (oid.equals(NISTObjectIdentifiers.id_sha512.getId())) {
      return "SHA-512";
    }
    if (oid.equals(X9_SHA1_WITH_ECDSA_OID)) {
      return "SHA1withECDSA";
    }
    if (oid.equals(X9_SHA224_WITH_ECDSA_OID)) {
      return "SHA224withECDSA";
    }
    if (oid.equals(X9_SHA256_WITH_ECDSA_OID)) {
      return "SHA256withECDSA";
    }
    if (oid.equals(X9_SHA384_WITH_ECDSA_OID)) {
      return "SHA384withECDSA";
    }
    if (oid.equals(X9_SHA512_WITH_ECDSA_OID)) {
      return "SHA512withECDSA";
    }
    if (oid.equals(PKCS1_RSA_OID)) {
      return "RSA";
    }
    if (oid.equals(PKCS1_MD2_WITH_RSA_OID)) {
      return "MD2withRSA";
    }
    if (oid.equals(PKCS1_MD4_WITH_RSA_OID)) {
      return "MD4withRSA";
    }
    if (oid.equals(PKCS1_MD5_WITH_RSA_OID)) {
      return "MD5withRSA";
    }
    if (oid.equals(PKCS1_SHA1_WITH_RSA_OID)) {
      return "SHA1withRSA";
    }
    if (oid.equals(PKCS1_SHA256_WITH_RSA_OID)) {
      return "SHA256withRSA";
    }
    if (oid.equals(PKCS1_SHA384_WITH_RSA_OID)) {
      return "SHA384withRSA";
    }
    if (oid.equals(PKCS1_SHA512_WITH_RSA_OID)) {
      return "SHA512withRSA";
    }
    if (oid.equals(PKCS1_SHA224_WITH_RSA_OID)) {
      return "SHA224withRSA";
    }
    if (oid.equals(IEEE_P1363_SHA1_OID)) {
      return "SHA-1";
    }
    if (oid.equals(PKCS1_RSASSA_PSS_OID)) {
      return "SSAwithRSA/PSS";
    }
    if (oid.equals(PKCS1_MGF1)) {
      return "MGF1";
    }

    throw new NoSuchAlgorithmException("Unknown OID " + oid);
  }

  /**
   * Looks up an object identifier for the given JCE mnemonic.
   *
   * @param name a JCE mnemonic string
   *
   * @return an object identifier if known
   *
   * @throws NoSuchAlgorithmException if the mnemonic does not correspond to a known object identifier
   */
  public static String lookupOIDByMnemonic(String name) throws NoSuchAlgorithmException {
    if ("O".equals(name)) {
      return X509ObjectIdentifiers.organization.getId();
    }
    if ("OU".equals(name)) {
      return X509ObjectIdentifiers.organizationalUnitName.getId();
    }
    if ("CN".equals(name)) {
      return X509ObjectIdentifiers.commonName.getId();
    }
    if ("C".equals(name)) {
      return X509ObjectIdentifiers.countryName.getId();
    }
    if ("ST".equals(name)) {
      return X509ObjectIdentifiers.stateOrProvinceName.getId();
    }
    if ("L".equals(name)) {
      return X509ObjectIdentifiers.localityName.getId();
    }
    if ("SHA-1".equalsIgnoreCase(name) || "SHA1".equalsIgnoreCase(name)) {
      return X509ObjectIdentifiers.id_SHA1.getId();
    }
    if ("SHA-224".equalsIgnoreCase(name) || "SHA224".equalsIgnoreCase(name)) {
      return NISTObjectIdentifiers.id_sha224.getId();
    }
    if ("SHA-256".equalsIgnoreCase(name) || "SHA256".equalsIgnoreCase(name)) {
      return NISTObjectIdentifiers.id_sha256.getId();
    }
    if ("SHA-384".equalsIgnoreCase(name) || "SHA384".equalsIgnoreCase(name)) {
      return NISTObjectIdentifiers.id_sha384.getId();
    }
    if ("SHA-512".equalsIgnoreCase(name) || "SHA512".equalsIgnoreCase(name)) {
      return NISTObjectIdentifiers.id_sha512.getId();
    }
    if ("RSA".equalsIgnoreCase(name)) {
      return PKCS1_RSA_OID;
    }
    if ("MD2withRSA".equalsIgnoreCase(name)) {
      return PKCS1_MD2_WITH_RSA_OID;
    }
    if ("MD4withRSA".equalsIgnoreCase(name)) {
      return PKCS1_MD4_WITH_RSA_OID;
    }
    if ("MD5withRSA".equalsIgnoreCase(name)) {
      return PKCS1_MD5_WITH_RSA_OID;
    }
    if ("SHA1withRSA".equalsIgnoreCase(name)) {
      return PKCS1_SHA1_WITH_RSA_OID;
    }
    if ("SHA256withRSA".equalsIgnoreCase(name)) {
      return PKCS1_SHA256_WITH_RSA_OID;
    }
    if ("SHA384withRSA".equalsIgnoreCase(name)) {
      return PKCS1_SHA384_WITH_RSA_OID;
    }
    if ("SHA512withRSA".equalsIgnoreCase(name)) {
      return PKCS1_SHA512_WITH_RSA_OID;
    }
    if ("SHA224withRSA".equalsIgnoreCase(name)) {
      return PKCS1_SHA224_WITH_RSA_OID;
    }
    if ("SHA1withECDSA".equalsIgnoreCase(name)) {
      return X9_SHA1_WITH_ECDSA_OID;
    }
    if ("SHA224withECDSA".equalsIgnoreCase(name)) {
      return X9_SHA224_WITH_ECDSA_OID;
    }
    if ("SHA256withECDSA".equalsIgnoreCase(name)) {
      return X9_SHA256_WITH_ECDSA_OID;
    }
    if ("SHA384withECDSA".equalsIgnoreCase(name)) {
      return X9_SHA384_WITH_ECDSA_OID;
    }
    if ("SHA512withECDSA".equalsIgnoreCase(name)) {
      return X9_SHA512_WITH_ECDSA_OID;
    }
    if ("SAwithRSA/PSS".equalsIgnoreCase(name)) {
      return PKCS1_RSASSA_PSS_OID;
    }
    if ("SSAwithRSA/PSS".equalsIgnoreCase(name)) {
      return PKCS1_RSASSA_PSS_OID;
    }
    if ("RSASSA-PSS".equalsIgnoreCase(name)) {
      return PKCS1_RSASSA_PSS_OID;
    }
    if ("MGF1".equalsIgnoreCase(name)) {
      return PKCS1_MGF1;
    }
    if ("SHA256withRSAandMGF1".equalsIgnoreCase(name)) {
      return PKCS1_MGF1;
    }
    if ("SHA512withRSAandMGF1".equalsIgnoreCase(name)) {
      return PKCS1_MGF1;
    }

    throw new NoSuchAlgorithmException("Unknown name " + name);
  }

  /* PRIVATE BELOW */

  /**
   * Checks that the content actually digests to the hash value contained in the message digest attribute.
   *
   * @param attributes the attributes, this should contain an attribute of type {@link #RFC_3369_MESSAGE_DIGEST_OID}
   * @param digAlg the digest algorithm
   * @param contentBytes the contents
   *
   * @throws NoSuchAlgorithmException if the digest algorithm is unsupported
   * @throws SignatureException if the reported digest does not correspond to the computed digest
   */
  private static void checkEContent(Collection<Attribute> attributes, String digAlg, byte[] contentBytes) throws NoSuchAlgorithmException, SignatureException {
    for (Attribute attribute: attributes) {
      if (!RFC_3369_MESSAGE_DIGEST_OID.equals(attribute.getAttrType().getId())) {
        continue;
      }

      ASN1Set attrValuesSet = attribute.getAttrValues();
      if (attrValuesSet.size() != 1) {
        LOGGER.warning("Expected only one attribute value in signedAttribute message digest in eContent!");
      }
      byte[] storedDigestedContent = ((DEROctetString)attrValuesSet.getObjectAt(0)).getOctets();

      if (storedDigestedContent == null) {
        LOGGER.warning("Error extracting signedAttribute message digest in eContent!");
      }

      MessageDigest dig = MessageDigest.getInstance(digAlg);
      byte[] computedDigestedContent = dig.digest(contentBytes);
      if (!Arrays.equals(storedDigestedContent, computedDigestedContent)) {
        throw new SignatureException("Error checking signedAttribute message digest in eContent!");
      }
    }
  }

  /**
   * Extracts the attributes as a Java list from the BC ASN1 encoded signed attributes set structure.
   *
   * @param signedAttributesSet the BC ASN1 encoded signed attributes set structure
   *
   * @return the attributes as a Java list
   */
  private static List<Attribute> getAttributes(ASN1Set signedAttributesSet) {
    List<ASN1Sequence> attributeObjects = Collections.list(signedAttributesSet.getObjects());
    List<Attribute> attributes = new ArrayList<Attribute>(attributeObjects.size());
    for (ASN1Sequence attributeObject: attributeObjects) {
      Attribute attribute = Attribute.getInstance(attributeObject);
      attributes.add(attribute);
    }
    return attributes;
  }

  /**
   * Converts the BC RSA-SSA parameter specification to a JCE parameter specification.
   *
   * @param rsaSSAParams the RSA-SSA parameter specification to convert
   *
   * @return a corresponding JCE parameter specification
   *
   * @throws NoSuchAlgorithmException on error
   */
  private static AlgorithmParameterSpec toAlgorithmParameterSpec(RSASSAPSSparams rsaSSAParams) throws NoSuchAlgorithmException {
    String hashAlgorithmOID = rsaSSAParams.getHashAlgorithm().getAlgorithm().getId();
    AlgorithmIdentifier maskGenAlgorithm = rsaSSAParams.getMaskGenAlgorithm();
    String maskGenAlgorithmOID = maskGenAlgorithm.getAlgorithm().getId();

    String hashAlgorithmName = lookupMnemonicByOID(hashAlgorithmOID);
    String maskGenAlgorithmName = lookupMnemonicByOID(maskGenAlgorithmOID);

    int saltLength = rsaSSAParams.getSaltLength().intValue();
    int trailerField = rsaSSAParams.getTrailerField().intValue();

    return new PSSParameterSpec(hashAlgorithmName, maskGenAlgorithmName, toMaskGenAlgorithmParameterSpec(maskGenAlgorithm), saltLength, trailerField);
  }

  /**
   * Converts the BC algorithm identifier (used in RSA-SSA) to a JCE algorithm parameter specification.
   *
   * @param maskGenAlgorithm the algorithm identifier to convert
   *
   * @return the corresponding JCE algorithm parameter specification
   */
  private static AlgorithmParameterSpec toMaskGenAlgorithmParameterSpec(AlgorithmIdentifier maskGenAlgorithm) {
    try {
      ASN1Encodable maskGenParams = maskGenAlgorithm.getParameters();
      if (maskGenParams != null) {
        AlgorithmIdentifier hashIdentifier = AlgorithmIdentifier.getInstance(maskGenParams);
        String hashOID = hashIdentifier.getAlgorithm().getId();
        String hashName = lookupMnemonicByOID(hashOID);
        return new MGF1ParameterSpec(hashName);
      }
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
    }
    /* Default to SHA-1. */
    return new MGF1ParameterSpec("SHA-1");
  }

  /**
   * Extracts the signer info structure from a signed data structure.
   *
   * @param signedData the signed data structure
   *
   * @return the signer info structure
   */
  private static SignerInfo getSignerInfo(SignedData signedData)  {
    ASN1Set signerInfos = signedData.getSignerInfos();
    if (signerInfos == null || signerInfos.size() <= 0) {
      throw new IllegalArgumentException("No signer info in signed data");
    }

    if (signerInfos.size() > 1) {
      LOGGER.warning("Found " + signerInfos.size() + " signerInfos");
    }

    return SignerInfo.getInstance(signerInfos.getObjectAt(0));
  }

  /**
   * Creates a singleton ASN1 set containing the given BC ASN1 object.
   *
   * @param e the ASN1 object
   *
   * @return an ASN1 set containing the given object as single element
   */
  private static ASN1Set createSingletonSet(ASN1Object e) {
    return new DLSet(new ASN1Encodable[] { e });
  }
}
