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
 * $Id: EACTAResult.java 1799 2018-10-30 16:25:48Z martijno $
 */

package org.jmrtd.protocol;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.Util;
import org.jmrtd.cert.CVCPrincipal;
import org.jmrtd.cert.CardVerifiableCertificate;

import net.sf.scuba.util.Hex;

/**
 * Result of EAC Terminal Authentication protocol.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1799 $
 */
public class EACTAResult implements Serializable {

  private static final long serialVersionUID = -2926063872890928748L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private EACCAResult chipAuthenticationResult;
  private CVCPrincipal caReference;
  private List<CardVerifiableCertificate> terminalCertificates = new ArrayList<CardVerifiableCertificate>();
  private PrivateKey terminalKey;
  private String documentNumber;
  private byte[] cardChallenge;

  /**
   * Constructs a new terminal authentication result.
   *
   * @param caResult the chip authentication result
   * @param caReference the certificate authority
   * @param terminalCertificates terminal certificates
   * @param terminalKey the terminal's private key
   * @param documentNumber the documentNumber
   * @param cardChallenge the challenge
   */
  public EACTAResult(EACCAResult caResult, CVCPrincipal caReference,
      List<CardVerifiableCertificate> terminalCertificates, PrivateKey terminalKey,
      String documentNumber, byte[] cardChallenge) {
    this.chipAuthenticationResult = caResult;
    this.caReference = caReference;
    for (CardVerifiableCertificate terinalCertificate: terminalCertificates) {
      this.terminalCertificates.add(terinalCertificate);
    }
    this.terminalKey = terminalKey;
    this.documentNumber = documentNumber;
    this.cardChallenge = cardChallenge;
  }

  /**
   * Returns the chip authentication result.
   *
   * @return the chip authenticaiton result
   */
  public EACCAResult getChipAuthenticationResult() {
    return chipAuthenticationResult;
  }

  /**
   * Returns CA certificate's reference used during EAC-TA.
   *
   * @return CA certificate's reference
   */
  public CVCPrincipal getCAReference() {
    return caReference;
  }

  /**
   * Returns the chain of card verifiable certificates that is to be used
   * for authenticating the PCD to the ICC.
   *
   * @return the chain of CVCertificates used to authenticate the terminal to
   *         the card
   */
  public List<CardVerifiableCertificate> getCVCertificates() {
    return terminalCertificates;
  }

  /**
   * Returns the PCD's private key used during EAC.
   *
   * @return the PCD's private key
   */
  public PrivateKey getTerminalKey() {
    return terminalKey;
  }

  /**
   * Returns the identifier of the card used during EAC.
   *
   * @return the id of the card
   */
  public String getDocumentNumber() {
    return documentNumber;
  }

  /**
   * Returns the card's challenge generated during EAC.
   *
   * @return the card's challenge
   */
  public byte[] getCardChallenge() {
    return cardChallenge;
  }

  /**
   * Returns a textual representation of this terminal authentication result.
   *
   * @return a textual representation of this terminal authentication result
   */
  @Override
  public String toString() {
    StringBuilder result = new StringBuilder();
    result.append("TAResult [chipAuthenticationResult: " + chipAuthenticationResult).append(", ");
    result.append("caReference: " + caReference).append(", ");
    result.append("terminalCertificates: [");
    boolean isFirst = true;
    for (CardVerifiableCertificate cert: terminalCertificates) {
      if (isFirst) {
        isFirst = false;
      } else {
        result.append(", ");
      }
      result.append(toString(cert));
    }
    result.append("terminalKey = ").append(Util.getDetailedPrivateKeyAlgorithm(terminalKey)).append(", ");
    result.append("documentNumber = ").append(documentNumber).append(", ");
    result.append("cardChallenge = ").append(Hex.bytesToHexString(cardChallenge)).append(", ");
    result.append("]");
    return result.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((caReference == null) ? 0 : caReference.hashCode());
    result = prime * result + Arrays.hashCode(cardChallenge);
    result = prime * result + ((chipAuthenticationResult == null) ? 0 : chipAuthenticationResult.hashCode());
    result = prime * result + ((documentNumber == null) ? 0 : documentNumber.hashCode());
    result = prime * result + ((terminalCertificates == null) ? 0 : terminalCertificates.hashCode());
    result = prime * result + ((terminalKey == null) ? 0 : terminalKey.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    EACTAResult other = (EACTAResult) obj;
    if (caReference == null) {
      if (other.caReference != null) {
        return false;
      }
    } else if (!caReference.equals(other.caReference)) {
      return false;
    }
    if (!Arrays.equals(cardChallenge, other.cardChallenge)) {
      return false;
    }
    if (chipAuthenticationResult == null) {
      if (other.chipAuthenticationResult != null) {
        return false;
      }
    } else if (!chipAuthenticationResult.equals(other.chipAuthenticationResult)) {
      return false;
    }
    if (documentNumber == null) {
      if (other.documentNumber != null) {
        return false;
      }
    } else if (!documentNumber.equals(other.documentNumber)) {
      return false;
    }
    if (terminalCertificates == null) {
      if (other.terminalCertificates != null) {
        return false;
      }
    } else if (!terminalCertificates.equals(other.terminalCertificates)) {
      return false;
    }
    if (terminalKey == null) {
      return other.terminalKey == null;
    }

    return terminalKey.equals(other.terminalKey);
  }

  /**
   * Returns a textual representation of the certificate.
   *
   * @param certificate the certificate
   *
   * @return a textual representation of the certificate
   */
  private Object toString(CardVerifiableCertificate certificate) {
    StringBuilder result = new StringBuilder();
    result.append("CardVerifiableCertificate [");
    try {
      CVCPrincipal reference = certificate.getHolderReference();
      if (!caReference.equals(reference)) {
        result.append("holderReference: " + reference);
      }
    } catch (CertificateException ce) {
      result.append("holderReference = ???");
      LOGGER.log(Level.WARNING, "Exception", ce);
    }

    result.append("]");

    return result.toString();
  }
}
