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
 * $Id: AbstractMRTDCardService.java 1800 2018-10-31 14:15:55Z martijno $
 */

package org.jmrtd;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;

import javax.crypto.SecretKey;

import org.jmrtd.cert.CVCPrincipal;
import org.jmrtd.cert.CardVerifiableCertificate;
import org.jmrtd.protocol.AAResult;
import org.jmrtd.protocol.BACResult;
import org.jmrtd.protocol.EACCAResult;
import org.jmrtd.protocol.EACTAResult;
import org.jmrtd.protocol.PACEResult;
import org.jmrtd.protocol.SecureMessagingWrapper;

import net.sf.scuba.smartcards.CardServiceException;

/**
 * Base class for MRTD card services.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1800 $
 *
 * @since 0.7.0
 */
public abstract class AbstractMRTDCardService extends FileSystemCardService {

  /**
   * Performs the <i>Basic Access Control</i> protocol.
   *
   * @param bacKey the key based on the document number,
   *               the card holder's birth date,
   *               and the document's expiration date
   *
   * @return the BAC result
   *
   * @throws CardServiceException if authentication failed
   */
  public abstract BACResult doBAC(AccessKeySpec bacKey) throws CardServiceException;

  /**
   * Performs the <i>Basic Access Control</i> protocol.
   * It does BAC using kEnc and kMac keys, usually calculated
   * from the document number, the card holder's date of birth,
   * and the card's date of expiry.
   *
   * A secure messaging channel is set up as a result.
   *
   * @param kEnc static 3DES key required for BAC
   * @param kMac static 3DES key required for BAC
   *
   * @return the result
   *
   * @throws CardServiceException if authentication failed
   * @throws GeneralSecurityException on security primitives related problems
   */
  public abstract BACResult doBAC(SecretKey kEnc, SecretKey kMac) throws CardServiceException, GeneralSecurityException;

  /**
   * Performs the PACE 2.0 / SAC protocol.
   * A secure messaging channel is set up as a result.
   *
   * @param keySpec the MRZ
   * @param oid as specified in the PACEInfo, indicates GM or IM or CAM, DH or ECDH, cipher, digest, length
   * @param params explicit static domain parameters the domain params for DH or ECDH
   *
   * @return the result
   *
   * @throws CardServiceException if authentication failed or on error
   */
  public abstract PACEResult doPACE(AccessKeySpec keySpec, String oid, AlgorithmParameterSpec params, BigInteger parameterId) throws CardServiceException;

  /**
   * Selects the card side applet. If PACE has been executed successfully previously, then the card has authenticated
   * us and a secure messaging channel has already been established. If not, then the caller should request BAC execution
   * as a next step.
   *
   * @param shouldUseSecureMessaging indicates whether a secure messaging channel has already been established
   *                                 (which is the case if PACE has been executed)
   *
   * @throws CardServiceException on error
   */
  public abstract void sendSelectApplet(boolean shouldUseSecureMessaging) throws CardServiceException;

  /**
   * Performs the <i>Active Authentication</i> protocol.
   *
   * @param publicKey the public key to use (usually read from the card)
   * @param digestAlgorithm the digest algorithm to use, or null
   * @param signatureAlgorithm signature algorithm
   * @param challenge challenge
   *
   * @return a boolean indicating whether the card was authenticated
   *
   * @throws CardServiceException on error
   */
  public abstract AAResult doAA(PublicKey publicKey, String digestAlgorithm, String signatureAlgorithm, byte[] challenge) throws CardServiceException;

  /**
   * Perform CA (Chip Authentication) part of EAC (version 1). For details see TR-03110
   * ver. 1.11. In short, we authenticate the chip with (EC)DH key agreement
   * protocol and create new secure messaging keys.
   * A new secure messaging channel is set up as a result.
   *
   * @param keyId the chip's public key id (stored in DG14), {@code null} if none
   * @param oid the object identifier indicating the Chip Authentication protocol
   * @param publicKeyOID the object identifier indicating the public key algorithm used
   * @param publicKey passport's public key (stored in DG14)
   *
   * @return the Chip Authentication result
   *
   * @throws CardServiceException if CA failed or some error occurred
   */
  public abstract EACCAResult doEACCA(BigInteger keyId, String oid, String publicKeyOID, PublicKey publicKey) throws CardServiceException;

  /**
   * Performs <i>Terminal Authentication</i> (TA) part of EAC (version 1). For details see
   * TR-03110 ver. 1.11.
   *
   * In short, we feed the sequence of terminal certificates to the card for verification,
   * get a challenge from the card, sign it with the terminal private key, and send the result
   * back to the card for verification.
   *
   * @param caReference reference issuer
   * @param terminalCertificates terminal certificate chain
   * @param terminalKey terminal private key
   * @param taAlg algorithm
   * @param chipAuthenticationResult the chip authentication result
   * @param documentNumber the document number
   *
   * @return the Terminal Authentication result
   *
   * @throws CardServiceException on error
   */
  public abstract EACTAResult doEACTA(CVCPrincipal caReference, List<CardVerifiableCertificate> terminalCertificates,
      PrivateKey terminalKey, String taAlg, EACCAResult chipAuthenticationResult, String documentNumber) throws CardServiceException;

  /**
   * Performs <i>Terminal Authentication</i> (TA) part of EAC (version 1). For details see
   * TR-03110 ver. 1.11.
   *
   * In short, we feed the sequence of terminal certificates to the card for verification,
   * get a challenge from the card, sign it with the terminal private key, and send the result
   * back to the card for verification.
   *
   * @param caReference reference issuer
   * @param terminalCertificates terminal certificate chain
   * @param terminalKey terminal private key
   * @param taAlg algorithm
   * @param chipAuthenticationResult the chip authentication result
   * @param paceResult the PACE result
   *
   * @return the Terminal Authentication result
   *
   * @throws CardServiceException on error
   */
  public abstract EACTAResult doEACTA(CVCPrincipal caReference, List<CardVerifiableCertificate> terminalCertificates,
      PrivateKey terminalKey, String taAlg, EACCAResult chipAuthenticationResult, PACEResult paceResult) throws CardServiceException;

  /**
   * Returns the secure messaging wrapper currently in use.
   *
   * @return the secure messaging wrapper
   */
  public abstract SecureMessagingWrapper getWrapper();
}
