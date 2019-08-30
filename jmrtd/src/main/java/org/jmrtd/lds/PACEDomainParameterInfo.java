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
 * $Id: PACEDomainParameterInfo.java 1808 2019-03-07 21:32:19Z martijno $
 */

package org.jmrtd.lds;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.jmrtd.Util;

/**
 * PACE Domain Parameter Info object as per SAC TR 1.01, November 11, 2010.
 *
 * The object identifier dhpublicnumber or ecPublicKey for DH or ECDH, respectively, SHALL be used to reference
 * explicit domain parameters in an AlgorithmIdentifier (cf. Section 9.1):
 *
 * <pre>
 *    dhpublicnumber OBJECT IDENTIFIER ::= {
 *        iso(1) member-body(2) us(840) ansi-x942(10046) number-type(2) 1
 *    }
 * </pre>
 * <pre>
 *    ecPublicKey OBJECT IDENTIFIER ::= {
 *        iso(1) member-body(2) us(840) ansi-x962(10045) keyType(2) 1
 *    }
 * </pre>
 *
 * In the case of elliptic curves, domain parameters MUST be described explicitly in the ECParameters structure,
 * contained as parameters in the AlgorithmIdentifier, i.e. named curves and implicit domain parameters MUST NOT
 * be used.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1808 $
 *
 * @since 0.5.0
 */
public class PACEDomainParameterInfo extends SecurityInfo {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  private static final long serialVersionUID = -5851251908152594728L;

  /**
   * Value for parameter algorithm OID (part of parameters AlgorithmIdentifier).
   */
  public static final String ID_PRIME_FIELD = "1.2.840.10045.1.1";

  /**
   * Value for parameter algorithm OID (part of parameters AlgorithmIdentifier).
   * <code>ecPublicKey OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) ansi-x962(10045) keyType(2) 1 }</code>.
   */
  public static final String ID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";

  /**
   * Value for parameter algorithm OID (part of parameters AlgorithmIdentifier).
   * <code>dhpublicnumber OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) ansi-x942(10046) number-type(2) 1 }</code>.
   */
  public static final String ID_DH_PUBLIC_NUMBER = "1.2.840.10046.2.1";

  private String oid;

  /*
   * FIXME: This field is now transient, but should not be.
   *
   * We should serialize the contents of concrete instantiations explicitly.
   * Possibly by first defining PACEECDomainParameters and PACEDHDomainParameters subclasses
   * first (yet, ECParameterSpec and DHParameterSpec are also not Serializable).
   */
  private transient AlgorithmIdentifier domainParameter;

  private BigInteger parameterId;

  /**
   * Constructs a PACE domain parameter info structure.
   *
   * @param protocolOID must be {@link SecurityInfo#ID_PACE_DH_GM}, {@link SecurityInfo#ID_PACE_ECDH_GM},
   *                    {@link SecurityInfo#ID_PACE_DH_IM}, {@link SecurityInfo#ID_PACE_ECDH_IM}
   * @param domainParameter parameters in the form of algorithm identifier with algorithm
   *        1.2.840.10046.2.1 (DH public number) or 1.2.840.10045.2.1 (EC public key)
   */
  public PACEDomainParameterInfo(String protocolOID, AlgorithmIdentifier domainParameter) {
    this(protocolOID, domainParameter, null);
  }

  /**
   * Constructs a PACE domain parameter info structure.
   *
   * @param protocolOID must be {@link SecurityInfo#ID_PACE_DH_GM}, {@link SecurityInfo#ID_PACE_ECDH_GM},
   *                    {@link SecurityInfo#ID_PACE_DH_IM}, {@link SecurityInfo#ID_PACE_ECDH_IM}
   * @param domainParameter parameters in the form of algorithm identifier with algorithm
   *        1.2.840.10046.2.1 (DH public number) or 1.2.840.10045.2.1 (EC public key)
   * @param parameterId an identifier to identify this info
   */
  public PACEDomainParameterInfo(String protocolOID, AlgorithmIdentifier domainParameter, BigInteger parameterId) {
    if (!checkRequiredIdentifier(protocolOID)) {
      throw new IllegalArgumentException("Invalid protocol id: " + protocolOID);
    }

    this.oid = protocolOID;
    this.domainParameter = domainParameter;
    this.parameterId = parameterId;
  }

  @Override
  public String getObjectIdentifier() {
    return oid;
  }

  /**
   * Returns the protocol object identifier as a human readable string.
   *
   * @return a string
   */
  @Override
  public String getProtocolOIDString() {
    return toProtocolOIDString(oid);
  }

  /**
   * Returns the parameter id, or {@code null} if this is the only domain parameter info.
   *
   * @return the parameter id or {@code null}
   */
  public BigInteger getParameterId() {
    return parameterId;
  }

  /**
   * Returns the parameters in the form of algorithm identifier
   * with algorithm 1.2.840.10046.2.1 (DH public number)
   * or 1.2.840.10045.2.1 (EC public key).
   *
   * @return the parameters
   */
  public AlgorithmParameterSpec getParameters() {
    if (ID_DH_PUBLIC_NUMBER.equals(oid)) {
      throw new IllegalStateException("DH PACEDomainParameterInfo not yet implemented"); // FIXME
    } else if (ID_EC_PUBLIC_KEY.equals(oid)) {
      return toECParameterSpec(domainParameter);
    } else {
      throw new IllegalStateException("Unsupported PACEDomainParameterInfo type " + oid);
    }
  }

  /**
   * Returns a DER object with this {@code SecurityInfo} data (DER sequence).
   *
   * @return a DER object with this {@code SecurityInfo} data
   *
   * @deprecated Remove this method from visible interface (because of dependency on BC API)
   */
  @Deprecated
  @Override
  public ASN1Primitive getDERObject() {
    ASN1EncodableVector vector = new ASN1EncodableVector();

    /* Protocol */
    vector.add(new ASN1ObjectIdentifier(oid));

    /* Required data */
    vector.add(domainParameter);

    /* Optional data */
    if (parameterId != null) {
      vector.add(new ASN1Integer(parameterId));
    }
    return new DLSequence(vector);
  }

  @Override
  public String toString() {
    return new StringBuilder()
        .append("PACEDomainParameterInfo")
        .append("[")
        .append("protocol: ").append(toProtocolOIDString(oid))
        .append(", ")
        .append("domainParameter: [")
        .append("algorithm: ").append(domainParameter.getAlgorithm().getId()) // e.g. ID_EC_PUBLIC_KEY
        .append(", ")
        .append("parameters: ").append(domainParameter.getParameters()) // e.g. ASN1 sequence of length 6
        .append(parameterId == null ? "" : ", parameterId: " + parameterId)
        .append("]")
        .toString();
  }

  @Override
  public int hashCode() {
    return 111111111
        + 7 * oid.hashCode()
        + 5 * domainParameter.hashCode()
        + 3 * (parameterId == null ? 333 : parameterId.hashCode());
  }

  @Override
  public boolean equals(Object other) {
    if (other == null) {
      return false;
    }
    if (other == this) {
      return true;
    }
    if (!PACEDomainParameterInfo.class.equals(other.getClass())) {
      return false;
    }

    PACEDomainParameterInfo otherPACEDomainParameterInfo = (PACEDomainParameterInfo)other;
    return getDERObject().equals(otherPACEDomainParameterInfo.getDERObject());
  }

  /**
   * Checks whether the object identifier is an allowed PACE related object identifier.
   *
   * @param oid a string representing an object identifier
   *
   * @return a boolean indicating whether the object identifier is allowed
   */
  public static boolean checkRequiredIdentifier(String oid) {
    return ID_PACE_DH_GM.equals(oid)
        || ID_PACE_ECDH_GM.equals(oid)
        || ID_PACE_DH_IM.equals(oid)
        || ID_PACE_ECDH_IM.equals(oid)
        || ID_PACE_ECDH_CAM.equals(oid);
  }

  /* TODO: toAlgorithmIdentifier for DH case. */

  /**
   * Returns a BC algorithm identifier object from an EC parameter spec.
   *
   * @param ecParameterSpec the EC parameter spec
   *
   * @return the BC algorithm identifier object
   *
   * @deprecated Visibility will be restricted
   */
  @Deprecated
  public static AlgorithmIdentifier toAlgorithmIdentifier(ECParameterSpec ecParameterSpec) {
    List<ASN1Encodable> paramSequenceList = new ArrayList<ASN1Encodable>();

    ASN1Integer versionObject = new ASN1Integer(BigInteger.ONE);
    paramSequenceList.add(versionObject);

    ASN1ObjectIdentifier fieldIdOID = new ASN1ObjectIdentifier(ID_PRIME_FIELD);
    EllipticCurve curve = ecParameterSpec.getCurve();
    ECFieldFp field = (ECFieldFp)curve.getField();
    ASN1Integer p = new ASN1Integer(field.getP());
    ASN1Sequence fieldIdObject = new DLSequence(new ASN1Encodable[] { fieldIdOID, p });
    paramSequenceList.add(fieldIdObject);

    ASN1OctetString aObject = new DEROctetString(Util.i2os(curve.getA()));
    ASN1OctetString bObject = new DEROctetString(Util.i2os(curve.getB()));
    ASN1Sequence curveObject = new DLSequence(new ASN1Encodable[] { aObject, bObject });
    paramSequenceList.add(curveObject);

    ASN1OctetString basePointObject = new DEROctetString(Util.ecPoint2OS(ecParameterSpec.getGenerator()));
    paramSequenceList.add(basePointObject);

    ASN1Integer orderObject = new ASN1Integer(ecParameterSpec.getOrder());
    paramSequenceList.add(orderObject);

    ASN1Integer coFactorObject = new ASN1Integer(ecParameterSpec.getCofactor());
    paramSequenceList.add(coFactorObject);

    ASN1Encodable[] paramSequenceArray = new ASN1Encodable[paramSequenceList.size()];
    paramSequenceList.toArray(paramSequenceArray);
    ASN1Sequence paramSequence = new DLSequence(paramSequenceArray);
    return new AlgorithmIdentifier(new ASN1ObjectIdentifier(PACEDomainParameterInfo.ID_EC_PUBLIC_KEY), paramSequence);
  }

  /* TODO: toDHParameterSpec for DH case. */

  /**
   * Returns the EC parameter spec form the BC algorithm identifier object.
   *
   * @param domainParameter the BC algorithm identifier object
   *
   * @return an EC parameter spec
   *
   * @deprecated Visibility will be restricted
   */
  @Deprecated
  public static ECParameterSpec toECParameterSpec(AlgorithmIdentifier domainParameter) {
    ASN1Encodable parameters = domainParameter.getParameters();

    if (!(parameters instanceof ASN1Sequence)) {
      throw new IllegalArgumentException("Was expecting an ASN.1 sequence");
    }

    /* We support named EC curves, even though they are actually not allowed here. */
    try {
      X962Parameters x962params = X962Parameters.getInstance(parameters);
      if (x962params.isNamedCurve()) {
        ASN1ObjectIdentifier x96ParamsOID = (ASN1ObjectIdentifier)x962params.getParameters();
        X9ECParameters x9ECParams = X962NamedCurves.getByOID(x96ParamsOID);
        ECNamedCurveParameterSpec bcECNamedCurveParams =
          new ECNamedCurveParameterSpec(X962NamedCurves.getName(x96ParamsOID), x9ECParams.getCurve(), x9ECParams.getG(),
            x9ECParams.getN(), x9ECParams.getH(), x9ECParams.getSeed());
        return Util.toECNamedCurveSpec(bcECNamedCurveParams);
      }
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
    }

    /* Explicit EC parameters. */

    /*
     * ECParameters ::= SEQUENCE {
     *     version INTEGER { ecpVer1(1) } (ecpVer1),
     *     fieldID FieldID {{FieldTypes}},
     *     curve Curve,
     *     base ECPoint,
     *     order INTEGER,
     *     cofactor INTEGER OPTIONAL,
     *     ...
     * }
     */

    ASN1Sequence paramSequence = (ASN1Sequence)parameters;

    if (paramSequence.size() < 5) {
      throw new IllegalArgumentException("Was expecting an ASN.1 sequence of length 5 or longer");
    }

    try {
      ASN1Integer versionObject = (ASN1Integer)paramSequence.getObjectAt(0);
      /* BigInteger version = */ (versionObject).getValue();
      //        assert BigInteger.ONE.equals(version);

      ASN1Sequence fieldIdObject = (ASN1Sequence)paramSequence.getObjectAt(1);
      //        assert 2 == fieldIdObject.size();
      /* String fieldIdOID = */ ((ASN1ObjectIdentifier)fieldIdObject.getObjectAt(0)).getId();
      //        assert ID_PRIME_FIELD.equals(fieldIdOID);
      BigInteger p = ((ASN1Integer)fieldIdObject.getObjectAt(1)).getPositiveValue();

      ASN1Sequence curveObject = (ASN1Sequence)paramSequence.getObjectAt(2);
      //        assert 2 == curveObject.size();
      ASN1OctetString aObject = (ASN1OctetString)curveObject.getObjectAt(0);
      ASN1OctetString bObject = (ASN1OctetString)curveObject.getObjectAt(1);
      BigInteger a = Util.os2i(aObject.getOctets());
      BigInteger b = Util.os2i(bObject.getOctets());

      ASN1OctetString basePointObject = (ASN1OctetString)paramSequence.getObjectAt(3);
      ECPoint g = Util.os2ECPoint(basePointObject.getOctets());
      BigInteger x = g.getAffineX();
      BigInteger y = g.getAffineY();
      // assert G is on the curve
      BigInteger lhs = y.pow(2).mod(p);
      BigInteger xPow3 = x.pow(3);
      BigInteger rhs = xPow3.add(a.multiply(x)).add(b).mod(p);

      EllipticCurve curve = new EllipticCurve(new ECFieldFp(p), a, b);

      ASN1Integer orderObject = (ASN1Integer)paramSequence.getObjectAt(4);
      BigInteger n = orderObject.getPositiveValue();

      if (paramSequence.size() <= 5) {
        return new ECParameterSpec(curve, g, n, 1);
      } else {
        ASN1Integer coFactorObject = (ASN1Integer)paramSequence.getObjectAt(5);
        BigInteger coFactor = coFactorObject.getValue();
        return new ECParameterSpec(curve, g, n, coFactor.intValue());
      }
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception", e);
      throw new IllegalArgumentException("Could not get EC parameters from explicit parameters");
    }
  }

  /* ONLY PRIVATE METHODS BELOW */

  /**
   * Returns an BC algorithm identifier for the given protocol object identifier.
   *
   * @param protocolOID the protocol object identifier
   * @param parameters the parameters as a BC ASN1 encodable
   *
   * @return an algorithm identifier
   */
  private static AlgorithmIdentifier toAlgorithmIdentifier(String protocolOID, ASN1Encodable parameters) {
    if (ID_PACE_DH_GM.equals(protocolOID)
        || ID_PACE_DH_IM.equals(protocolOID)) {
      return new AlgorithmIdentifier(new ASN1ObjectIdentifier(ID_DH_PUBLIC_NUMBER), parameters);
    } else if (ID_PACE_ECDH_GM.equals(protocolOID)
        || ID_PACE_ECDH_IM.equals(protocolOID)
        || ID_PACE_ECDH_CAM.equals(protocolOID)) {
      return new AlgorithmIdentifier(new ASN1ObjectIdentifier(ID_EC_PUBLIC_KEY), parameters);
    }
    throw new IllegalArgumentException("Cannot infer algorithm OID from protocol OID: " + protocolOID);
  }

  /**
   * Returns an ASN1 name for the give object identifier.
   *
   * @param oid an object identifier
   *
   * @return an ASN1 name
   */
  private static String toProtocolOIDString(String oid) {
    if (ID_PACE_DH_GM.equals(oid)) {
      return "id-PACE-DH-GM";
    }
    if (ID_PACE_ECDH_GM.equals(oid)) {
      return "id-PACE-ECDH-GM";
    }
    if (ID_PACE_DH_IM.equals(oid)) {
      return "id-PACE-DH-IM";
    }
    if (ID_PACE_ECDH_IM.equals(oid)) {
      return "id-PACE-ECDH-IM";
    }
    if (ID_PACE_ECDH_CAM.equals(oid)) {
      return "id-PACE-ECDH-CAM";
    }

    return oid;
  }
}
