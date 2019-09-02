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
 * $Id: PassportService.java 1799 2018-10-30 16:25:48Z martijno $
 */

package org.jmrtd;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import org.jmrtd.cert.CVCPrincipal;
import org.jmrtd.cert.CardVerifiableCertificate;
import org.jmrtd.protocol.AAAPDUSender;
import org.jmrtd.protocol.AAProtocol;
import org.jmrtd.protocol.AAResult;
import org.jmrtd.protocol.BACAPDUSender;
import org.jmrtd.protocol.BACProtocol;
import org.jmrtd.protocol.BACResult;
import org.jmrtd.protocol.EACCAAPDUSender;
import org.jmrtd.protocol.EACCAProtocol;
import org.jmrtd.protocol.EACCAResult;
import org.jmrtd.protocol.EACTAAPDUSender;
import org.jmrtd.protocol.EACTAProtocol;
import org.jmrtd.protocol.EACTAResult;
import org.jmrtd.protocol.PACEAPDUSender;
import org.jmrtd.protocol.PACEProtocol;
import org.jmrtd.protocol.PACEResult;
import org.jmrtd.protocol.ReadBinaryAPDUSender;
import org.jmrtd.protocol.SecureMessagingWrapper;

import net.sf.scuba.smartcards.APDUListener;
import net.sf.scuba.smartcards.CardFileInputStream;
import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ResponseAPDU;

/**
 * Card service for reading files (such as data groups) and using the various
 * access control protocols (BAC, PACE, EAC-TA), clone-detection verification
 * protocols (AA, EAC-CA), and the resulting secure messaging as implemented
 * by the MRTD ICC.
 *
 * Based on ICAO Doc 9303 2015.
 * Originally based on ICAO-TR-PKI and ICAO-TR-LDS.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision:352 $
 */
public class PassportService extends AbstractMRTDCardService {

  /** Shared secret type for non-PACE key. */
  public static final byte NO_PACE_KEY_REFERENCE = 0x00;

  /** Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1. */
  public static final byte MRZ_PACE_KEY_REFERENCE = 0x01;

  /** Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1. */
  public static final byte CAN_PACE_KEY_REFERENCE = 0x02;

  /** Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1. */
  public static final byte PIN_PACE_KEY_REFERENCE = 0x03;

  /** Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1. */
  public static final byte PUK_PACE_KEY_REFERENCE = 0x04;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /** Card Access. */
  public static final short EF_CARD_ACCESS = 0x011C;

  /** Card Security. */
  public static final short EF_CARD_SECURITY = 0x011D;

  /** File identifier for data group 1. Data group 1 contains the MRZ. */
  public static final short EF_DG1 = 0x0101;

  /** File identifier for data group 2. Data group 2 contains face image data. */
  public static final short EF_DG2 = 0x0102;

  /** File identifier for data group 3. Data group 3 contains finger print data. */
  public static final short EF_DG3 = 0x0103;

  /** File identifier for data group 4. Data group 4 contains iris data. */
  public static final short EF_DG4 = 0x0104;

  /** File identifier for data group 5. Data group 5 contains displayed portrait. */
  public static final short EF_DG5 = 0x0105;

  /** File identifier for data group 6. Data group 6 is RFU. */
  public static final short EF_DG6 = 0x0106;

  /** File identifier for data group 7. Data group 7 contains displayed signature. */
  public static final short EF_DG7 = 0x0107;

  /** File identifier for data group 8. Data group 8 contains data features. */
  public static final short EF_DG8 = 0x0108;

  /** File identifier for data group 9. Data group 9 contains structure features. */
  public static final short EF_DG9 = 0x0109;

  /** File identifier for data group 10. Data group 10 contains substance features. */
  public static final short EF_DG10 = 0x010A;

  /** File identifier for data group 11. Data group 11 contains additional personal details. */
  public static final short EF_DG11 = 0x010B;

  /** File identifier for data group 12. Data group 12 contains additional document details. */
  public static final short EF_DG12 = 0x010C;

  /** File identifier for data group 13. Data group 13 contains optional details. */
  public static final short EF_DG13 = 0x010D;

  /** File identifier for data group 14. Data group 14 contains security infos. */
  public static final short EF_DG14 = 0x010E;

  /** File identifier for data group 15. Data group 15 contains the public key used for Active Authentication. */
  public static final short EF_DG15 = 0x010F;

  /** File identifier for data group 16. Data group 16 contains person(s) to notify. */
  public static final short EF_DG16 = 0x0110;

  /** The security document. */
  public static final short EF_SOD = 0x011D;

  /** The data group presence list. */
  public static final short EF_COM = 0x011E;

  /**
   * Contains EAC CVA references. Note: this can be overridden by a file
   * identifier in the DG14 file (in a TerminalAuthenticationInfo). Check DG14
   * first. Also, this file does not have a header tag, like the others.
   */
  public static final short EF_CVCA = 0x011C;

  /** Short file identifier for card access file. */
  public static final byte SFI_CARD_ACCESS = 0x1C;

  /** Short file identifier for card security file. */
  public static final byte SFI_CARD_SECURITY = 0x1D;

  /** Short file identifier for file. */
  public static final byte SFI_DG1 = 0x01;

  /** Short file identifier for file. */
  public static final byte SFI_DG2 = 0x02;

  /** Short file identifier for file. */
  public static final byte SFI_DG3 = 0x03;

  /** Short file identifier for file. */
  public static final byte SFI_DG4 = 0x04;

  /** Short file identifier for file. */
  public static final byte SFI_DG5 = 0x05;

  /** Short file identifier for file. */
  public static final byte SFI_DG6 = 0x06;

  /** Short file identifier for file. */
  public static final byte SFI_DG7 = 0x07;

  /** Short file identifier for file. */
  public static final byte SFI_DG8 = 0x08;

  /** Short file identifier for file. */
  public static final byte SFI_DG9 = 0x09;

  /** Short file identifier for file. */
  public static final byte SFI_DG10 = 0x0A;

  /** Short file identifier for file. */
  public static final byte SFI_DG11 = 0x0B;

  /** Short file identifier for file. */
  public static final byte SFI_DG12 = 0x0C;

  /** Short file identifier for file. */
  public static final byte SFI_DG13 = 0x0D;

  /** Short file identifier for file. */
  public static final byte SFI_DG14 = 0x0E;

  /** Short file identifier for file. */
  public static final byte SFI_DG15 = 0x0F;

  /** Short file identifier for file. */
  public static final byte SFI_DG16 = 0x10;

  /** Short file identifier for file. */
  public static final byte SFI_COM = 0x1E;

  /** Short file identifier for file. */
  public static final byte SFI_SOD = 0x1D;

  /** Short file identifier for file. */
  public static final byte SFI_CVCA = 0x1C;

  /** The default maximal blocksize used for unencrypted APDUs. */
  public static final int DEFAULT_MAX_BLOCKSIZE = 224;

  /** The normal maximal tranceive length of APDUs. */
  public static final int NORMAL_MAX_TRANCEIVE_LENGTH = 256;

  /** The extended maximal tranceive length of APDUs. */
  public static final int EXTENDED_MAX_TRANCEIVE_LENGTH = 65536;

  /** The applet we select when we start a session. */
  protected static final byte[] APPLET_AID = { (byte)0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };

  /**
   * The file read block size, some passports cannot handle large values.
   */
  private int maxBlockSize;

  private boolean isOpen;

  private SecureMessagingWrapper wrapper;

  private int maxTranceiveLength;

  private boolean shouldCheckMAC;

  private boolean isAppletSelected;

  private DefaultFileSystem rootFileSystem;

  private DefaultFileSystem appletFileSystem;

  private BACAPDUSender bacSender;
  private PACEAPDUSender paceSender;
  private AAAPDUSender aaSender;
  private EACCAAPDUSender eacCASender;
  private EACTAAPDUSender eacTASender;
  private ReadBinaryAPDUSender readBinarySender;

  private CardService service;

  /**
   * Creates a new passport service for accessing the passport.
   *
   * @param service another service which will deal with sending the APDUs to the card
   * @param maxTranceiveLength maximum length for APDUs
   * @param maxBlockSize maximum buffer size for plain text APDUs
   * @param isSFIEnabled whether short file identifiers should be used for read binaries when possible
   * @param shouldCheckMAC whether the secure messaging channels, resulting from BAC, PACE, EAC-CA, should
   *                       check MACs on response APDUs
   */
  public PassportService(CardService service, int maxTranceiveLength, int maxBlockSize, boolean isSFIEnabled, boolean shouldCheckMAC) {
    this.service = service;

    this.bacSender = new BACAPDUSender(service);
    this.paceSender = new PACEAPDUSender(service);
    this.aaSender = new AAAPDUSender(service);
    this.eacCASender = new EACCAAPDUSender(service);
    this.eacTASender = new EACTAAPDUSender(service);
    this.readBinarySender = new ReadBinaryAPDUSender(service);

    this.maxTranceiveLength = maxTranceiveLength;
    this.maxBlockSize = maxBlockSize;
    this.shouldCheckMAC = shouldCheckMAC;
    this.isAppletSelected = false;
    this.isOpen = false;

    this.rootFileSystem = new DefaultFileSystem(readBinarySender, false); // Some passports (UK?) don't support SFI for EF.CardAccess. -- MO
    this.appletFileSystem = new DefaultFileSystem(readBinarySender, isSFIEnabled);
  }

  /**
   * Opens a session to the card. As of 0.4.10 this no longer auto selects the passport application,
   * caller is responsible to call #sendSelectApplet(boolean) now.
   *
   * @throws CardServiceException on error
   */
  @Override
  public void open() throws CardServiceException {
    if (isOpen()) {
      return;
    }
    synchronized(this) {
      service.open();
      isOpen = true;
    }
  }

  /**
   * Selects the card side applet. If PACE has been executed successfully previously, then the ICC has authenticated
   * us and a secure messaging channel has already been established. If not, then the caller should request BAC execution as a next
   * step.
   *
   * @param hasPACESucceeded indicates whether PACE has been executed successfully (in which case a secure messaging channel has been established)
   *
   * @throws CardServiceException on error
   */
  public void sendSelectApplet(boolean hasPACESucceeded) throws CardServiceException {
    if (isAppletSelected) {
      LOGGER.info("Re-selecting ICAO applet");
    }

    if (hasPACESucceeded) {
      /* Use SM as set up by doPACE() */
      readBinarySender.sendSelectApplet(wrapper, APPLET_AID);
    } else {
      /* Use plain messaging to select the applet, caller will have to do doBAC. */
      readBinarySender.sendSelectApplet(null, APPLET_AID);
    }

    isAppletSelected = true;
  }

  /**
   * Returns a boolean that indicates whether this service is open.
   *
   * @return a boolean that indicates whether this service is open
   */
  @Override
  public boolean isOpen() {
    return isOpen;
  }

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
  public synchronized BACResult doBAC(AccessKeySpec bacKey) throws CardServiceException {
    if (!(bacKey instanceof BACKeySpec)) {
      throw new IllegalArgumentException("Unsupported key type");
    }
    BACResult bacResult = (new BACProtocol(bacSender, maxTranceiveLength, shouldCheckMAC)).doBAC((BACKeySpec)bacKey);
    wrapper = bacResult.getWrapper();
    appletFileSystem.setWrapper(wrapper);
    return bacResult;
  }

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
  public synchronized BACResult doBAC(SecretKey kEnc, SecretKey kMac) throws CardServiceException, GeneralSecurityException {
    BACResult bacResult = (new BACProtocol(bacSender, maxTranceiveLength, shouldCheckMAC)).doBAC(kEnc, kMac);
    wrapper = bacResult.getWrapper();
    appletFileSystem.setWrapper(wrapper);
    return bacResult;
  }

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
   * @throws CardServiceException on error
   */
  public synchronized PACEResult doPACE(AccessKeySpec keySpec, String oid, AlgorithmParameterSpec params, BigInteger parameterId) throws CardServiceException {
    PACEResult paceResult = (new PACEProtocol(paceSender, wrapper, maxTranceiveLength, shouldCheckMAC)).doPACE(keySpec, oid, params, parameterId);
    wrapper = paceResult.getWrapper();
    appletFileSystem.setWrapper(wrapper);
    return paceResult;
  }

  /**
   * Perform CA (Chip Authentication) part of EAC (version 1). For details see TR-03110
   * ver. 1.11. In short, we authenticate the chip with (EC)DH key agreement
   * protocol and create new secure messaging keys.
   * A new secure messaging channel is set up as a result.
   *
   * @param keyId passport's public key id (stored in DG14), {@code null} if none
   * @param oid the object identifier indicating the Chip Authentication protocol
   * @param publicKeyOID the object identifier indicating the public key algorithm used
   * @param publicKey passport's public key (stored in DG14)
   *
   * @return the Chip Authentication result
   *
   * @throws CardServiceException if CA failed or some error occurred
   */
  public synchronized EACCAResult doEACCA(BigInteger keyId, String oid, String publicKeyOID, PublicKey publicKey) throws CardServiceException {
    EACCAResult caResult = (new EACCAProtocol(eacCASender, wrapper, maxTranceiveLength, shouldCheckMAC)).doCA(keyId, oid, publicKeyOID, publicKey);
    wrapper = caResult.getWrapper();
    appletFileSystem.setWrapper(wrapper);
    return caResult;
  }

  /* From BSI-03110 v1.1, B.2:
   *
   * <pre>
   * The following sequence of commands SHALL be used to implement Terminal Authentication:
   *   1. MSE:Set DST
   *   2. PSO:Verify Certificate
   *   3. MSE:Set AT
   *   4. Get Challenge
   *   5. External Authenticate
   * Steps 1 and 2 are repeated for every CV certificate to be verified
   * (CVCA Link Certificates, DV Certificate, IS Certificate).
   * </pre>
   */
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
  public synchronized EACTAResult doEACTA(CVCPrincipal caReference, List<CardVerifiableCertificate> terminalCertificates,
      PrivateKey terminalKey, String taAlg, EACCAResult chipAuthenticationResult, String documentNumber) throws CardServiceException {
    return (new EACTAProtocol(eacTASender, wrapper)).doEACTA(caReference, terminalCertificates, terminalKey, taAlg, chipAuthenticationResult, documentNumber);
  }

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
  public synchronized EACTAResult doEACTA(CVCPrincipal caReference, List<CardVerifiableCertificate> terminalCertificates,
      PrivateKey terminalKey, String taAlg, EACCAResult chipAuthenticationResult, PACEResult paceResult) throws CardServiceException {
    return (new EACTAProtocol(eacTASender, wrapper)).doTA(caReference, terminalCertificates, terminalKey, taAlg, chipAuthenticationResult, paceResult);
  }

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
  public AAResult doAA(PublicKey publicKey, String digestAlgorithm, String signatureAlgorithm, byte[] challenge) throws CardServiceException {
    return (new AAProtocol(aaSender, wrapper)).doAA(publicKey, digestAlgorithm, signatureAlgorithm, challenge);
  }

  /**
   * Closes this service.
   */
  @Override
  public void close() {
    try {
      service.close();
      wrapper = null;
    } finally {
      isOpen = false;
    }
  }

  /**
   * Returns the maximum tranceive length of (protected) APDUs.
   *
   * @return the maximum APDU tranceive length
   */
  public int getMaxTranceiveLength() {
    return maxTranceiveLength;
  }

  /**
   * Returns the secure messaging wrapper currently in use.
   * Returns {@code null} until access control has been performed.
   *
   * @return the wrapper
   */
  public SecureMessagingWrapper getWrapper() {
    return wrapper;
  }

  @Override
  public ResponseAPDU transmit(CommandAPDU commandAPDU) throws CardServiceException {
    return service.transmit(commandAPDU);
  }

  /**
   * Returns the answer to reset.
   *
   * @return the answer to reset
   *
   * @throws CardServiceException on error
   */
  @Override
  public byte[] getATR() throws CardServiceException {
    return service.getATR();
  }

  /**
   * Determines whether an exception indicates a tag is lost event.
   *
   * @param e an exception
   *
   * @return whether the exception indicates a tag is lost event
   */
  @Override
  public boolean isConnectionLost(Exception e) {
    return service.isConnectionLost(e);
  }

  /**
   * Whether secure channels should check the MAC on response APDUs sent by the ICC.
   *
   * @return a boolean indicating whether the MAC should be checked
   */
  public boolean shouldCheckMAC() {
    return shouldCheckMAC;
  }

  /**
   * Returns the file indicated by the file identifier as an input stream.
   * The resulting input stream will send APDUs to the card as it is being read.
   *
   * @param fid the file identifier
   *
   * @return the file as an input stream
   *
   * @throws CardServiceException if the file cannot be read
   */
  public synchronized CardFileInputStream getInputStream(short fid) throws CardServiceException {
    if (!isAppletSelected) {
      synchronized(rootFileSystem) {
        rootFileSystem.selectFile(fid);
        return new CardFileInputStream(maxBlockSize, rootFileSystem);
      }
    } else {
      synchronized(appletFileSystem) {
        appletFileSystem.selectFile(fid);
        return new CardFileInputStream(maxBlockSize, appletFileSystem);
      }
    }
  }

  @Override
  public void addAPDUListener(APDUListener l) {
    service.addAPDUListener(l);
  }

  @Override
  public void removeAPDUListener(APDUListener l) {
    service.removeAPDUListener(l);
  }
}
