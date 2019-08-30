/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2017  The JMRTD team
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
 * $Id: EACTAProtocol.java 1802 2018-11-06 16:29:28Z martijno $
 */

package org.jmrtd.protocol;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.util.List;

import javax.crypto.interfaces.DHPublicKey;

import org.jmrtd.APDULevelEACTACapable;
import org.jmrtd.Util;
import org.jmrtd.cert.CVCAuthorizationTemplate.Role;
import org.jmrtd.cert.CVCPrincipal;
import org.jmrtd.cert.CardVerifiableCertificate;
import org.jmrtd.lds.icao.MRZInfo;

import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.tlv.TLVOutputStream;
import net.sf.scuba.tlv.TLVUtil;

/**
 * The EAC Terminal Authentication protocol.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1802 $
 *
 * @since 0.5.6
 */
public class EACTAProtocol {

  private static final int TAG_CVCERTIFICATE_SIGNATURE = 0x5F37;

  private static final Provider BC_PROVIDER = Util.getBouncyCastleProvider();

  private APDULevelEACTACapable service;

  private SecureMessagingWrapper wrapper;

  /**
   * Creates a protocol instance.
   *
   * @param service the card service for APDU communication
   * @param wrapper the secure messaging wrapper
   */
  public EACTAProtocol(APDULevelEACTACapable service, SecureMessagingWrapper wrapper) {
    this.service = service;
    this.wrapper = wrapper;
  }

  /*
   * From BSI-03110 v1.1, B.2:
   *
   * <pre>
   * The following sequence of commands SHALL be used to implement Terminal
   * Authentication:
   *    1. MSE:Set DST
   *    2. PSO:Verify Certificate
   *    3. MSE:Set AT
   *    4. Get Challenge
   *    5. External Authenticate
   *
   * Steps 1 and 2 are repeated for every CV certificate to be verified
   * (CVCA Link Certificates, DV Certificate, IS Certificate).
   * </pre>
   */

  /**
   * Perform the EAC-TA (Terminal Authentication) part of EAC (version 1).
   * For details see TR-03110 ver. 1.11. In short, we feed the sequence of
   * terminal certificates to the card for verification, get a challenge
   * from the card, sign it with terminal private key, and send back to
   * the card for verification.
   *
   * @param caReference a reference to the issuer
   * @param terminalCertificates the terminal certificate chain
   * @param terminalKey the terminal private key
   * @param taAlg the algorithm
   * @param chipAuthenticationResult the chip authentication result
   * @param documentNumber the document number from which the chip key hash will be derived
   *
   * @return the Terminal Authentication result
   *
   * @throws CardServiceException on error
   */
  public synchronized EACTAResult doEACTA(CVCPrincipal caReference, List<CardVerifiableCertificate> terminalCertificates,
      PrivateKey terminalKey, String taAlg, EACCAResult chipAuthenticationResult, String documentNumber) throws CardServiceException {
    byte[] idPICC = deriveIdentifier(documentNumber);
    return doTA(caReference, terminalCertificates, terminalKey, taAlg, chipAuthenticationResult, idPICC);
  }

  /**
   * Perform TA (Terminal Authentication) part of EAC (version 1). For details see
   * TR-03110 ver. 1.11. In short, we feed the sequence of terminal certificates
   * to the card for verification, get a challenge from the card, sign it with
   * terminal private key, and send back to the card for verification.
   *
   * @param caReference reference issuer
   * @param terminalCertificates terminal certificate chain
   * @param terminalKey terminal private key
   * @param taAlg the algorithm
   * @param chipAuthenticationResult the chip authentication result
   * @param paceResult the PACE result from which the chip key hash will be derived
   *
   * @return the Terminal Authentication result
   *
   * @throws CardServiceException on error
   */
  public synchronized EACTAResult doTA(CVCPrincipal caReference, List<CardVerifiableCertificate> terminalCertificates,
      PrivateKey terminalKey, String taAlg, EACCAResult chipAuthenticationResult, PACEResult paceResult) throws CardServiceException {
    try {
      byte[] idPICC = deriveIdentifier(paceResult);
      return doTA(caReference, terminalCertificates, terminalKey, taAlg, chipAuthenticationResult, idPICC);
    } catch (NoSuchAlgorithmException e) {
      throw new CardServiceException("No such algorithm", e);
    }
  }

  /**
   * Executes the Terminal Authentication protocol.
   *
   * @param caReference the certificate authority
   * @param terminalCertificates the chain of certificates to send
   * @param terminalKey the inspection system's private key
   * @param taAlg the algorithm
   * @param chipAuthenticationResult the result of the Chip Authentication protocol execution
   * @param idPICC the chip identifier
   *
   * @return the result of Terminal Authentication
   *
   * @throws CardServiceException on error
   */
  public synchronized EACTAResult doTA(CVCPrincipal caReference, List<CardVerifiableCertificate> terminalCertificates,
      PrivateKey terminalKey, String taAlg, EACCAResult chipAuthenticationResult, byte[] idPICC) throws CardServiceException {
    try {
      if (terminalCertificates == null || terminalCertificates.isEmpty()) {
        throw new IllegalArgumentException("Need at least 1 certificate to perform TA, found: " + terminalCertificates);
      }

      byte[] caKeyHash = chipAuthenticationResult.getKeyHash();
      /* The key hash that resulted from CA. */
      if (caKeyHash == null) {
        throw new IllegalArgumentException("CA key hash is null");
      }

      /*
       * FIXME: check that terminalCertificates holds a (inverted, i.e. issuer before
       * subject) chain.
       */

      /*
       * Check if first cert is/has the expected CVCA, and remove it from chain if it
       * is the CVCA.
       */
      CardVerifiableCertificate firstCert = terminalCertificates.get(0);
      Role firstCertRole = firstCert.getAuthorizationTemplate().getRole();
      if (Role.CVCA.equals(firstCertRole)) {
        CVCPrincipal firstCertHolderReference = firstCert.getHolderReference();
        if (caReference != null && !caReference.equals(firstCertHolderReference)) {
          throw new CardServiceException("First certificate holds wrong authority, found \""
              + firstCertHolderReference.getName() + "\", expected \"" + caReference.getName() + "\"");
        }
        if (caReference == null) {
          caReference = firstCertHolderReference;
        }
        terminalCertificates.remove(0);
      }
      CVCPrincipal firstCertAuthorityReference = firstCert.getAuthorityReference();
      if (caReference != null && !caReference.equals(firstCertAuthorityReference)) {
        throw new CardServiceException("First certificate not signed by expected CA, found "
            + firstCertAuthorityReference.getName() + ", expected " + caReference.getName());
      }
      if (caReference == null) {
        caReference = firstCertAuthorityReference;
      }

      /* Check if the last cert is an IS cert. */
      CardVerifiableCertificate lastCert = terminalCertificates.get(terminalCertificates.size() - 1);
      Role lastCertRole = lastCert.getAuthorizationTemplate().getRole();
      if (!Role.IS.equals(lastCertRole)) {
        throw new CardServiceException("Last certificate in chain (" + lastCert.getHolderReference().getName()
            + ") does not have role IS, but has role " + lastCertRole);
      }
      CardVerifiableCertificate terminalCert = lastCert;

      /* Have the MRTD check our chain. */
      for (CardVerifiableCertificate cert: terminalCertificates) {
        try {
          CVCPrincipal authorityReference = cert.getAuthorityReference();

          /* Step 1: MSE:SetDST */
          /*
           * Manage Security Environment: Set for verification: Digital Signature
           * Template, indicate authority of cert to check.
           */
          byte[] authorityRefBytes = TLVUtil.wrapDO(0x83, authorityReference.getName().getBytes("ISO-8859-1"));
          service.sendMSESetDST(wrapper, authorityRefBytes);

          /* Cert body is already in TLV format. */
          byte[] body = cert.getCertBodyData();

          /* Signature not yet in TLV format, prefix it with tag and length. */
          byte[] signature = cert.getSignature();
          ByteArrayOutputStream sigOut = new ByteArrayOutputStream();
          TLVOutputStream tlvSigOut = new TLVOutputStream(sigOut);
          tlvSigOut.writeTag(TAG_CVCERTIFICATE_SIGNATURE);
          tlvSigOut.writeValue(signature);
          tlvSigOut.close();
          signature = sigOut.toByteArray();

          /* Step 2: PSO:Verify Certificate */
          service.sendPSOExtendedLengthMode(wrapper, body, signature);
        } catch (CardServiceException cse) {
          throw cse;
        } catch (Exception e) {
          /* FIXME: Does this mean we failed to authenticate? -- MO */
          throw new CardServiceException("Exception", e);
        }
      }

      if (terminalKey == null) {
        throw new CardServiceException("No terminal key");
      }

      /* Step 3: MSE Set AT */
      CVCPrincipal holderRef = terminalCert.getHolderReference();
      byte[] holderRefBytes = TLVUtil.wrapDO(0x83, holderRef.getName().getBytes("ISO-8859-1"));
      /*
       * Manage Security Environment: Set for external authentication: Authentication
       * Template
       */
      service.sendMSESetATExtAuth(wrapper, holderRefBytes);

      /* Step 4: send get challenge */
      byte[] rPICC = service.sendGetChallenge(wrapper);

      /* Step 5: external authenticate. */
      ByteArrayOutputStream dtbs = new ByteArrayOutputStream();
      dtbs.write(idPICC);
      dtbs.write(rPICC);
      dtbs.write(caKeyHash);
      dtbs.close();
      byte[] dtbsBytes = dtbs.toByteArray();

      String sigAlg = terminalCert.getSigAlgName();
      if (sigAlg == null) {
        throw new IllegalStateException("Could not determine signature algorithm for terminal certificate " + terminalCert.getHolderReference().getName());
      }
      Signature sig = Signature.getInstance(sigAlg, BC_PROVIDER);
      sig.initSign(terminalKey);
      sig.update(dtbsBytes);
      byte[] signedData = sig.sign();
      if (sigAlg.toUpperCase().endsWith("ECDSA")) {
        int keySize = (int)Math.ceil(((org.bouncycastle.jce.interfaces.ECPrivateKey)terminalKey).getParameters().getCurve().getFieldSize() / 8.0); //TODO: Interop Ispra 20170925
        signedData = Util.getRawECDSASignature(signedData, keySize);
      }

      service.sendMutualAuthenticate(wrapper, signedData);
      return new EACTAResult(chipAuthenticationResult, caReference, terminalCertificates, terminalKey, null, rPICC);
    } catch (CardServiceException cse) {
      throw cse;
    } catch (Exception e) {
      throw new CardServiceException("Exception", e);
    }
  }

  /**
   * Derives a chip identifier from the document number (BAC MRZ based case).
   *
   * @param documentNumber the document number that was used for primary access control (typically BAC)
   *
   * @return the chip identifier
   */
  private static byte[] deriveIdentifier(String documentNumber) {
    int documentNumberLength = documentNumber.length();
    byte[] idPICC = new byte[documentNumberLength + 1];
    try {
      System.arraycopy(documentNumber.getBytes("ISO-8859-1"), 0, idPICC, 0, documentNumberLength);
      idPICC[documentNumberLength] = (byte)MRZInfo.checkDigit(documentNumber);
      return idPICC;
    } catch (UnsupportedEncodingException e) {
      /* NOTE: Never happens, ISO-8859-1 is always supported. */
      throw new IllegalStateException("Unsupported encoding", e);
    }
  }

  /**
   * Derives a chip identifier from a PACE result (PACE case).
   *
   * @param paceResult the PACE result
   *
   * @return the chip identifier
   *
   * @throws NoSuchAlgorithmException on error
   */
  private static byte[] deriveIdentifier(PACEResult paceResult) throws NoSuchAlgorithmException {
    String agreementAlg = paceResult.getAgreementAlg();
    PublicKey pcdPublicKey = paceResult.getPICCPublicKey();
    if ("DH".equals(agreementAlg)) {
      /* TODO: this is probably wrong, what should be hashed? */
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      return md.digest(getKeyData(agreementAlg, pcdPublicKey));
    } else if ("ECDH".equals(agreementAlg)) {
      org.bouncycastle.jce.interfaces.ECPublicKey pcdECPublicKey = (org.bouncycastle.jce.interfaces.ECPublicKey)pcdPublicKey;
      byte[] t = Util.i2os(pcdECPublicKey.getQ().getAffineXCoord().toBigInteger());
      return Util.alignKeyDataToSize(t, (int)Math.ceil(pcdECPublicKey.getParameters().getCurve().getFieldSize() / 8.0)); // TODO: Interop Ispra for SecP521r1 20170925.
    }

    throw new NoSuchAlgorithmException("Unsupported agreement algorithm " + agreementAlg);
  }

  /**
   * Returns the encoded public key data to be sent.
   *
   * @param agreementAlg the agreement algorithm, either {@code "DH"} or {@code "ECDH"}
   * @param pcdPublicKey the inspection system's public key
   *
   * @return the key data
   */
  private static byte[] getKeyData(String agreementAlg, PublicKey pcdPublicKey) {
    if ("DH".equals(agreementAlg)) {
      DHPublicKey pcdDHPublicKey = (DHPublicKey)pcdPublicKey;
      return Util.i2os(pcdDHPublicKey.getY());
    } else if ("ECDH".equals(agreementAlg)) {
      /* NOTE: Why are we not relying on JCE here, but on Bouncy instead? */
      org.bouncycastle.jce.interfaces.ECPublicKey pcdECPublicKey = (org.bouncycastle.jce.interfaces.ECPublicKey)pcdPublicKey;
      return pcdECPublicKey.getQ().getEncoded(false);
    }

    throw new IllegalArgumentException("Unsupported agreement algorithm " + agreementAlg);
  }
}

