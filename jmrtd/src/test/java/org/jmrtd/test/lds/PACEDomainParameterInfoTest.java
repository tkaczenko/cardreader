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
 * $Id: PACEDomainParameterInfoTest.java 1751 2018-01-15 15:35:45Z martijno $
 */

package org.jmrtd.test.lds;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.jce.ECPointUtil;
import org.jmrtd.lds.PACEDomainParameterInfo;

import junit.framework.TestCase;
import net.sf.scuba.util.Hex;

public class PACEDomainParameterInfoTest extends TestCase {

  private static final String ID_PRIME_FIELD = "1.2.840.10045.1.1";
  private static final String ID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";

  private static Logger LOGGER = Logger.getLogger("org.jmrtd");

  /**
   * Testing some internal functions here, these should be removed at some point.
   */
  public void testECParameterSpec() {
    try {
      ECParameterSpec ecParameterSpec = getSampleECParameterSpec();
      assertNotNull(ecParameterSpec);
      AlgorithmIdentifier algorithmIdentifier = PACEDomainParameterInfo.toAlgorithmIdentifier(ecParameterSpec);
      assertNotNull(algorithmIdentifier);
      assertEquals(ID_EC_PUBLIC_KEY, algorithmIdentifier.getAlgorithm().getId()); // 1.2.840.10045.2.1 - EC Public Key

      ASN1Encodable parameters = algorithmIdentifier.getParameters();
      ASN1Sequence paramSeq = ASN1Sequence.getInstance(parameters);
      X962Parameters x = X962Parameters.getInstance(paramSeq);
      assertNotNull(x);

      ECParameterSpec anotherECParameterSpec = PACEDomainParameterInfo.toECParameterSpec(algorithmIdentifier);
      assertEquals(ecParameterSpec.getCurve(), anotherECParameterSpec.getCurve());
      assertEquals(ecParameterSpec.getGenerator(), anotherECParameterSpec.getGenerator());
      assertEquals(ecParameterSpec.getOrder(), anotherECParameterSpec.getOrder());
      assertEquals(ecParameterSpec.getCofactor(), anotherECParameterSpec.getCofactor());

      /* Encoding and decoding... */

      byte[] encoded = algorithmIdentifier.getEncoded();
      assertNotNull(encoded);
      assertTrue(Arrays.equals(
          Hex.hexStringToBytes(
              "3081DE06072A8648CE3D02013081D2020101302906072A8648CE3D0101021E7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF3040041E7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC041E6B016C3BDCF18941D0D654921475CA71A9DB2FB27D1D37796185C2942C0A043D040FFA963CDCA8816CCC33B8642BEDF905C3D358573D3F27FBBD3B3CB9AAAF7DEBE8E4E90A5DAE6E4054CA530BA04654B36818CE226B39FCCB7B02F1AE021E7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF9E5E9A9F5D9071FBD1522688909D0B020101"),
          encoded));

      ASN1Object obj = null;
      ASN1InputStream asn1In = new ASN1InputStream(new ByteArrayInputStream(encoded));
      try {
        obj = asn1In.readObject();
      } finally {
        asn1In.close();
      }

      assertNotNull(obj);

      AlgorithmIdentifier decodedAlgorithmIdentifier = AlgorithmIdentifier.getInstance(obj);
      assertEquals(algorithmIdentifier, decodedAlgorithmIdentifier);
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      fail(e.getMessage());
    }
  }

  public ECParameterSpec getSampleECParameterSpec() {
    EllipticCurve curve = new EllipticCurve(new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), // q
        new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
        new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b
    ECParameterSpec ecSpec = new ECParameterSpec(curve, ECPointUtil.decodePoint(curve, Hex.hexStringToBytes("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
        new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), // n
        1); // h

    return ecSpec;
  }
}
