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
 * $Id: SODFileTest.java 1813 2019-06-06 14:43:07Z martijno $
 */

package org.jmrtd.test.lds;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jmrtd.Util;
import org.jmrtd.lds.LDSFile;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.icao.COMFile;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.test.ResourceUtil;

import junit.framework.TestCase;
import net.sf.scuba.util.Hex;

public class SODFileTest extends TestCase {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /** We need this for SHA-256 (and probably more). */
  private static final Provider BC_PROVIDER = Util.getBouncyCastleProvider();
  private static final String BC_PROVIDER_NAME = BC_PROVIDER == null ? null : BC_PROVIDER.getName();

  public SODFileTest(String name) {
    super(name);
  }

  public void testReflexive() {
    testReflexive(createTestObject("SHA-1", "SHA1WithRSA"));
    testReflexive(createTestObject("SHA-256", "SHA256WithRSA"));
    testReflexive(createTestObject("SHA-256", "SHA256WithECDSA"));
  }

  private byte[] readBytes(InputStream inputStream) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    int nRead;
    byte[] data = new byte[16384];
    while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
      buffer.write(data, 0, nRead);
    }
    buffer.flush();
    return buffer.toByteArray();
  }

  public void testDecodeEncode() {
    testDecodeEncode(createMustermannSampleInputStream());
  }

  public void testDecodeEncode(InputStream inputStream) {
    try {
      byte[] bytes = readBytes(inputStream);
      SODFile sodFile = new SODFile(new ByteArrayInputStream(bytes));
      byte[] encoded = sodFile.getEncoded();

      assertTrue(Arrays.equals(bytes, encoded));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Failed", e);
      fail(e.getMessage());
    }
  }

  public void testReflexive(SODFile sodFile) {
    try {
      byte[] encoded = sodFile.getEncoded();
      ByteArrayInputStream in = new ByteArrayInputStream(encoded);
      SODFile copy = new SODFile(in);
      assertEquals(sodFile, copy);
      assertEquals(Hex.bytesToHexString(encoded), Hex.bytesToHexString(copy.getEncoded()));
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  private static KeyPair createRSATestKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(1024);
    return keyPairGenerator.generateKeyPair();
  }

  private static KeyPair createECTestKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
    return keyPairGenerator.generateKeyPair();
  }

  public void testSODInFile(String file) {
    try {
      Provider[] providers = 	Security.getProviders();
      for (Provider provider: providers) {
        LOGGER.info("Security provider: " + provider);
      }
      SODFile sodFile = new SODFile(ResourceUtil.getInputStream(file));
      X509Certificate cert = sodFile.getDocSigningCertificate();
      BigInteger serial = cert == null ? null : cert.getSerialNumber();
      LOGGER.info("DEBUG: cert = " + (cert == null ? "null" : cert.toString()));
      LOGGER.info("DEBUG: serial number = " + (serial == null ? "null" : serial.toString()));
    } catch (FileNotFoundException e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      return; // inconclusive!
    } catch (Exception e) {
      fail(e.getMessage());
    }
  }

  public void testFields() {
    testFields(createTestObject("SHA-1", "SHA1WithRSA"));
    testFields(createTestObject("SHA-256", "SHA256WithRSA"));
    testFields(createTestObject("SHA-256", "SHA256WithECDSA"));
  }

  public void testFields(SODFile sodFile) {
    try {
      String ldsVersion = sodFile.getLDSVersion();
      assertTrue(ldsVersion == null || ldsVersion.length() == "aabb".length());

      String unicodeVersion = sodFile.getUnicodeVersion();
      assertTrue(unicodeVersion == null || unicodeVersion.length() == "aabbcc".length());

      X509Certificate certificate = sodFile.getDocSigningCertificate();

      BigInteger serialNumber = sodFile.getSerialNumber();

      if (serialNumber != null && certificate != null) {
        assertTrue("serialNumber = " + serialNumber + ", certificate.getSerialNumber() = " + certificate.getSerialNumber(),
            serialNumber.equals(certificate.getSerialNumber()));
      }

      X500Principal issuer = sodFile.getIssuerX500Principal();

      //      LOGGER.info("DEBUG: issuer = " + issuer);

      String issuerName = issuer.getName(X500Principal.RFC2253);
      assertNotNull(issuerName);

      if (issuer != null && certificate != null) {
        X500Principal certIssuer = certificate.getIssuerX500Principal();
        //        LOGGER.info("DEBUG: certIssuer = " + certIssuer);
        String certIssuerName = certIssuer.getName(X500Principal.RFC2253);
        assertNotNull(certIssuerName);
        //				assertTrue("issuerName = \"" + issuerName + "\", certIssuerName = \"" + certIssuerName + "\"",
        //						certIssuerName.equals(issuerName));
      }

      String digestAlgorithm = sodFile.getDigestAlgorithm();
      String digestEncryptionAlgorithm = sodFile.getDigestEncryptionAlgorithm();

      assertNotNull(digestAlgorithm);
      assertNotNull(digestEncryptionAlgorithm);
    } catch (Exception ce) {
      LOGGER.log(Level.WARNING, "Exception", ce);
      fail(ce.getMessage());
    }
  }

  public void testMustermann() {
    testFile(createMustermannSampleInputStream());
  }

  public void testFile(InputStream in) {
    try {
      SODFile sodFile = new SODFile(in);
      testReflexive(sodFile);
      testFields(sodFile);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
    }
  }

  public void testReconstructionViaOtherConstructor() {
    try {
      SODFile sodFile = createTestObject("SHA-1", "SHA256WithRSA");
      SODFile reconstructedSODFile = new SODFile(sodFile.getDigestAlgorithm(), sodFile.getDigestEncryptionAlgorithm(), sodFile.getDataGroupHashes(), sodFile.getEncryptedDigest(), sodFile.getDocSigningCertificate());
      assertEquals(sodFile, reconstructedSODFile);
      assertEquals(sodFile.getDigestAlgorithm(), reconstructedSODFile.getDigestAlgorithm());
      assertEquals(sodFile.getDigestEncryptionAlgorithm(), reconstructedSODFile.getDigestEncryptionAlgorithm());
      assertTrue(Arrays.equals(sodFile.getEContent(), reconstructedSODFile.getEContent()));
      assertEquals(new SODFile(new ByteArrayInputStream(sodFile.getEncoded())), reconstructedSODFile);
      assertEquals(new SODFile(new ByteArrayInputStream(reconstructedSODFile.getEncoded())), sodFile);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception" , e);
      fail(e.getMessage());
    }
  }

  public static SODFile createTestObject(String digestAlgorithm, String signatureAlgorithm) {
    try {
      Date today = Calendar.getInstance().getTime();
      DG1File dg1File = DG1FileTest.createTestObject();
      byte[] dg1Bytes = dg1File.getEncoded();
      DG2File dg2File = DG2FileTest.getDefaultTestObject();
      byte[] dg2Bytes = dg2File.getEncoded();
      //			DG15File dg15File = DG15FileTest.createTestObject();
      //			byte[] dg15Bytes = dg15File.getEncoded();

      KeyPair keyPair = signatureAlgorithm.endsWith("RSA") ? createRSATestKeyPair() : createECTestKeyPair();
      PublicKey publicKey = keyPair.getPublic();
      PrivateKey privateKey = keyPair.getPrivate();
      Date dateOfIssuing = today;
      Date dateOfExpiry = today;

      X509Certificate docSigningCert = generateDocSigningCert(BigInteger.ONE,
          "C=NL, O=State of the Netherlands, OU=Ministry of the Interior and Kingdom Relations, CN=CSCA NL",
          "C=NL, O=State of the Netherlands, OU=Ministry of the Interior and Kingdom Relations, CN=DS-01 NL, OID.2.5.4.5=1",
          dateOfIssuing,
          dateOfExpiry,
          publicKey,
          signatureAlgorithm,
          privateKey);

      Map<Integer, byte[]> hashes = new HashMap<Integer, byte[]>();
      MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
      hashes.put(1, digest.digest(dg1Bytes));
      hashes.put(2, digest.digest(dg2Bytes));
      //			hashes.put(15, digest.digest(dg15Bytes));
      //			byte[] encryptedDigest = new byte[128]; // Arbitrary value. Use a private key to generate a real signature?

      SODFile sod = new SODFile(digestAlgorithm, signatureAlgorithm, hashes, privateKey, docSigningCert);

      int[] dgPresenceList = { LDSFile.EF_DG1_TAG, LDSFile.EF_DG2_TAG };
      COMFile com = new COMFile("1.7", "4.0.0", dgPresenceList);

      //			File outputDir = new File("tmp");
      //			if (!outputDir.exists()) {
      //				if (!outputDir.mkdirs()) {
      //					fail("Could not make output dir \"" + outputDir.getAbsolutePath() + "\"");
      //				}
      //			}
      //			if (!outputDir.isDirectory()) {
      //				fail("Could not make output dir \"" + outputDir.getAbsolutePath() + "\"");
      //			}
      //
      //
      //			FileOutputStream comOut = new FileOutputStream(new File(outputDir, "EF_COM.bin"));
      //			comOut.write(com.getEncoded());
      //			comOut.flush();
      //			comOut.close();

      //			FileOutputStream dg1Out = new FileOutputStream(new File(outputDir, "DataGroup1.bin"));
      //			dg1Out.write(dg1File.getEncoded());
      //			dg1Out.flush();
      //			dg1Out.close();
      //
      //			FileOutputStream dg2Out = new FileOutputStream(new File(outputDir, "DataGroup2.bin"));
      //			dg2Out.write(dg2File.getEncoded());
      //			dg2Out.flush();
      //			dg2Out.close();
      //
      //			FileOutputStream sodOut = new FileOutputStream(new File(outputDir, "EF_SOD.bin"));
      //			sodOut.write(sod.getEncoded());
      //			sodOut.flush();
      //			sodOut.close();

      return sod;
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      return null;
    }
  }

  private static X509Certificate generateDocSigningCert(BigInteger serial, String issuerName, String subjectDN, Date dateOfIssuing, Date dateOfExpiry, PublicKey publicKey, String signatureAlgorithm, PrivateKey privateKey) throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, OperatorCreationException, IOException, CertificateException {
    SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
    X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(new X500Name(issuerName), serial, dateOfIssuing, dateOfExpiry, new X500Name(subjectDN), subjectPublicKeyInfo);
    ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BC_PROVIDER).build(privateKey);
    byte[] certBytes = certBuilder.build(signer).getEncoded();
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    return (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));
  }

  public InputStream createMustermannSampleInputStream() {
    try {
      return ResourceUtil.getInputStream("/lds/bsi2008/EF_SOD.bin");
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      fail(e.getMessage());
      return null;
    }
  }
}
