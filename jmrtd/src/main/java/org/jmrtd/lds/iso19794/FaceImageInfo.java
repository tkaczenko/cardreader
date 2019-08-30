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
 * $Id: FaceImageInfo.java 1808 2019-03-07 21:32:19Z martijno $
 */

package org.jmrtd.lds.iso19794;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.logging.Logger;

import org.jmrtd.lds.AbstractImageInfo;

import net.sf.scuba.data.Gender;

/**
 * Data structure for storing facial image data. This represents
 * a facial record data block as specified in Section 5.5, 5.6,
 * and 5.7 of ISO/IEC FCD 19794-5 (2004-03-22, AKA Annex D).
 *
 * A facial record data block contains a single facial image.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1808 $
 */
public class FaceImageInfo extends AbstractImageInfo {

  private static final long serialVersionUID = -1751069410327594067L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /** Eye color code based on Section 5.5.4 of ISO 19794-5. */
  public enum EyeColor {
    UNSPECIFIED(EYE_COLOR_UNSPECIFIED),
    BLACK(EYE_COLOR_BLACK),
    BLUE(EYE_COLOR_BLUE),
    BROWN(EYE_COLOR_BROWN),
    GRAY(EYE_COLOR_GRAY),
    GREEN(EYE_COLOR_GREEN),
    MULTI_COLORED(EYE_COLOR_MULTI_COLORED),
    PINK(EYE_COLOR_PINK),
    UNKNOWN(EYE_COLOR_UNKNOWN);

    private int code;

    /**
     * Creates an eye color.
     *
     * @param code the ISO19794-5 integer code for the color
     */
    private EyeColor(int code) {
      this.code = code;
    }

    /**
     * Returns the integer code to use in ISO19794-5 encoding for this color.
     *
     * @return the integer code
     */
    public int toInt() {
      return code;
    }

    /**
     * Returns an eye color value for the given code.
     *
     * @param i the integer code for a color
     *
     * @return the color value
     */
    static EyeColor toEyeColor(int i) {
      for (EyeColor c: EyeColor.values()) {
        if (c.toInt() == i) {
          return c;
        }
      }
      return UNKNOWN;
    }
  }

  /* These correspond to values in Table 4 in 5.5.4 in ISO/IEC 19794-5:2005(E). */
  public static final int EYE_COLOR_UNSPECIFIED = 0x00;
  public static final int EYE_COLOR_BLACK = 0x01;
  public static final int EYE_COLOR_BLUE = 0x02;
  public static final int EYE_COLOR_BROWN = 0x03;
  public static final int EYE_COLOR_GRAY = 0x04;
  public static final int EYE_COLOR_GREEN = 0x05;
  public static final int EYE_COLOR_MULTI_COLORED = 0x06;
  public static final int EYE_COLOR_PINK = 0x07;
  public static final int EYE_COLOR_UNKNOWN = 0xFF;

  /** Hair color code based on Section 5.5.5 of ISO 19794-5. */
  public enum HairColor {
    UNSPECIFIED(HAIR_COLOR_UNSPECIFIED),
    BALD(HAIR_COLOR_BALD),
    BLACK(HAIR_COLOR_BLACK),
    BLONDE(HAIR_COLOR_BLONDE),
    BROWN(HAIR_COLOR_BROWN),
    GRAY(HAIR_COLOR_GRAY),
    WHITE(HAIR_COLOR_WHITE),
    RED(HAIR_COLOR_RED),
    GREEN(HAIR_COLOR_GREEN),
    BLUE(HAIR_COLOR_BLUE),
    UNKNOWN(HAIR_COLOR_UNKNOWN);

    private int code;

    /**
     * Creates a hair color.
     *
     * @param code the integer code for a color
     */
    private HairColor(int code) {
      this.code = code;
    }

    /**
     * Returns the code for this hair color.
     *
     * @return the code
     */
    public int toInt() {
      return code;
    }

    /**
     * Returns a hair color value for the given code.
     *
     * @param i the integer code for a color
     *
     * @return the color value
     */
    static HairColor toHairColor(int i) {
      for (HairColor c: HairColor.values()) {
        if (c.toInt() == i) {
          return c;
        }
      }

      return UNKNOWN;
    }
  }

  public static final int HAIR_COLOR_UNSPECIFIED = 0x00;
  public static final int HAIR_COLOR_BALD = 0x01;
  public static final int HAIR_COLOR_BLACK = 0x02;
  public static final int HAIR_COLOR_BLONDE = 0x03;
  public static final int HAIR_COLOR_BROWN = 0x04;
  public static final int HAIR_COLOR_GRAY = 0x05;
  public static final int HAIR_COLOR_WHITE = 0x06;
  public static final int HAIR_COLOR_RED = 0x07;
  public static final int HAIR_COLOR_GREEN = 0x08;
  public static final int HAIR_COLOR_BLUE = 0x09;
  public static final int HAIR_COLOR_UNKNOWN = 0xFF;

  /** Feature flags meaning based on Section 5.5.6 of ISO 19794-5. */
  public enum Features {
    FEATURES_ARE_SPECIFIED,
    GLASSES,
    MOUSTACHE,
    BEARD,
    TEETH_VISIBLE,
    BLINK,
    MOUTH_OPEN,
    LEFT_EYE_PATCH,
    RIGHT_EYE_PATCH,
    DARK_GLASSES,
    DISTORTING_MEDICAL_CONDITION
  }

  private static final int FEATURE_FEATURES_ARE_SPECIFIED_FLAG = 0x000001;
  private static final int FEATURE_GLASSES_FLAG = 0x000002;
  private static final int FEATURE_MOUSTACHE_FLAG = 0x000004;
  private static final int FEATURE_BEARD_FLAG = 0x000008;
  private static final int FEATURE_TEETH_VISIBLE_FLAG = 0x000010;
  private static final int FEATURE_BLINK_FLAG = 0x000020;
  private static final int FEATURE_MOUTH_OPEN_FLAG = 0x000040;
  private static final int FEATURE_LEFT_EYE_PATCH_FLAG = 0x000080;
  private static final int FEATURE_RIGHT_EYE_PATCH = 0x000100;
  private static final int FEATURE_DARK_GLASSES = 0x000200;
  private static final int FEATURE_DISTORTING_MEDICAL_CONDITION = 0x000400;

  /** Expression code based on Section 5.5.7 of ISO 19794-5. */
  public enum Expression {
    UNSPECIFIED,
    NEUTRAL,
    SMILE_CLOSED,
    SMILE_OPEN,
    RAISED_EYEBROWS,
    EYES_LOOKING_AWAY,
    SQUINTING,
    FROWNING
  }

  public static final short EXPRESSION_UNSPECIFIED = 0x0000;
  public static final short EXPRESSION_NEUTRAL = 0x0001;
  public static final short EXPRESSION_SMILE_CLOSED = 0x0002;
  public static final short EXPRESSION_SMILE_OPEN = 0x0003;
  public static final short EXPRESSION_RAISED_EYEBROWS = 0x0004;
  public static final short EXPRESSION_EYES_LOOKING_AWAY = 0x0005;
  public static final short EXPRESSION_SQUINTING = 0x0006;
  public static final short EXPRESSION_FROWNING = 0x0007;

  /** Face image type code based on Section 5.7.1 of ISO 19794-5. */
  public enum FaceImageType {
    BASIC,
    FULL_FRONTAL,
    TOKEN_FRONTAL
  }

  public static final int FACE_IMAGE_TYPE_BASIC = 0x00;
  public static final int FACE_IMAGE_TYPE_FULL_FRONTAL = 0x01;
  public static final int FACE_IMAGE_TYPE_TOKEN_FRONTAL = 0x02;

  /** Image data type code based on Section 5.7.2 of ISO 19794-5. */
  public enum ImageDataType {
    TYPE_JPEG,
    TYPE_JPEG2000
  }

  public static final int IMAGE_DATA_TYPE_JPEG = 0x00;
  public static final int IMAGE_DATA_TYPE_JPEG2000 = 0x01;

  /** Color space code based on Section 5.7.4 of ISO 19794-5. */
  public enum ImageColorSpace {
    UNSPECIFIED,
    RGB24,
    YUV422,
    GRAY8,
    OTHER
  }

  public static final int IMAGE_COLOR_SPACE_UNSPECIFIED = 0x00;
  public static final int IMAGE_COLOR_SPACE_RGB24 = 0x01;
  public static final int IMAGE_COLOR_SPACE_YUV422 = 0x02;
  public static final int IMAGE_COLOR_SPACE_GRAY8 = 0x03;
  public static final int IMAGE_COLOR_SPACE_OTHER = 0x04;

  /** Source type based on Section 5.7.6 of ISO 19794-5. */
  public enum SourceType {
    UNSPECIFIED,
    STATIC_PHOTO_UNKNOWN_SOURCE,
    STATIC_PHOTO_DIGITAL_CAM,
    STATIC_PHOTO_SCANNER,
    VIDEO_FRAME_UNKNOWN_SOURCE,
    VIDEO_FRAME_ANALOG_CAM,
    VIDEO_FRAME_DIGITAL_CAM,
    UNKNOWN
  }

  public static final int SOURCE_TYPE_UNSPECIFIED = 0x00;
  public static final int SOURCE_TYPE_STATIC_PHOTO_UNKNOWN_SOURCE = 0x01;
  public static final int SOURCE_TYPE_STATIC_PHOTO_DIGITAL_CAM = 0x02;
  public static final int SOURCE_TYPE_STATIC_PHOTO_SCANNER = 0x03;
  public static final int SOURCE_TYPE_VIDEO_FRAME_UNKNOWN_SOURCE = 0x04;
  public static final int SOURCE_TYPE_VIDEO_FRAME_ANALOG_CAM = 0x05;
  public static final int SOURCE_TYPE_VIDEO_FRAME_DIGITAL_CAM = 0x06;
  public static final int SOURCE_TYPE_UNKNOWN = 0x07;

  /** Indexes into poseAngle array. */
  private static final int YAW = 0;

  /** Indexes into poseAngle array. */
  private static final int PITCH = 1;

  /** Indexes into poseAngle array. */
  private static final int ROLL = 2;

  private long recordLength;
  private Gender gender;
  private EyeColor eyeColor;
  private int hairColor;
  private int featureMask;
  private int expression;
  private int[] poseAngle;
  private int[] poseAngleUncertainty;
  private FeaturePoint[] featurePoints;
  private int faceImageType;
  private int imageDataType;
  private int colorSpace;
  private int sourceType;
  private int deviceType;
  private int quality;

  /**
   * Constructs a new face information data structure instance.
   *
   * @param gender gender
   * @param eyeColor eye color
   * @param featureMask feature mask (least significant 3 bytes)
   * @param hairColor hair color
   * @param expression expression
   * @param poseAngle (encoded) pose angle
   * @param poseAngleUncertainty pose angle uncertainty
   * @param faceImageType face image type
   * @param colorSpace color space
   * @param sourceType source type
   * @param deviceType capture device type (unspecified is <code>0x00</code>)
   * @param quality quality
   * @param featurePoints feature points
   * @param width width
   * @param height height
   * @param imageInputStream encoded image bytes
   * @param imageLength length of encoded image
   * @param imageDataType either IMAGE_DATA_TYPE_JPEG or IMAGE_DATA_TYPE_JPEG2000
   *
   * @throws IOException on error reading input
   */
  public FaceImageInfo(Gender gender, EyeColor eyeColor,
      int featureMask,
      int hairColor,
      int expression,
      int[] poseAngle, int[] poseAngleUncertainty,
      int faceImageType,
      int colorSpace,
      int sourceType,
      int deviceType,
      int quality,
      FeaturePoint[] featurePoints,
      int width, int height,
      InputStream imageInputStream, int imageLength, int imageDataType) throws IOException {
    super(TYPE_PORTRAIT, width, height, imageInputStream, imageLength, toMimeType(imageDataType));
    if (imageInputStream == null) {
      throw new IllegalArgumentException("Null image");
    }
    this.gender = gender == null ? Gender.UNSPECIFIED : gender;
    this.eyeColor = eyeColor == null ? EyeColor.UNSPECIFIED : eyeColor;
    this.featureMask = featureMask;
    this.hairColor = hairColor;
    this.expression = expression;
    this.colorSpace = colorSpace;
    this.sourceType = sourceType;
    this.deviceType = deviceType;
    int featurePointCount = featurePoints == null ? 0 : featurePoints.length;
    this.featurePoints = new FeaturePoint[featurePointCount];
    if (featurePointCount > 0) {
      System.arraycopy(featurePoints, 0, this.featurePoints, 0, featurePointCount);
    }
    this.poseAngle = new int[3];
    System.arraycopy(poseAngle, 0, this.poseAngle, 0, 3);
    this.poseAngleUncertainty = new int[3];
    System.arraycopy(poseAngleUncertainty, 0, this.poseAngleUncertainty, 0, 3);
    this.imageDataType = imageDataType;
    this.recordLength = 20L + 8 * featurePointCount + 12L + imageLength;

    this.faceImageType = faceImageType;
    this.colorSpace = colorSpace;
    this.sourceType = sourceType;
    this.deviceType = deviceType;
    this.quality = quality;
  }

  /**
   * Constructs a new face information structure from binary encoding.
   *
   * @param inputStream an input stream
   *
   * @throws IOException if input cannot be read
   */
  public FaceImageInfo(InputStream inputStream) throws IOException {
    super(TYPE_PORTRAIT);
    readObject(inputStream);
  }

  @Override
  protected void readObject(InputStream inputStream) throws IOException {
    DataInputStream dataIn = (inputStream instanceof DataInputStream) ? (DataInputStream)inputStream : new DataInputStream(inputStream);

    /* Facial Information Block (20), see ISO 19794-5 5.5 */
    recordLength = dataIn.readInt() & 0xFFFFFFFFL; /* 4 */
    int featurePointCount = dataIn.readUnsignedShort(); /* +2 = 6 */
    gender = Gender.getInstance(dataIn.readUnsignedByte()); /* +1 = 7 */
    eyeColor = EyeColor.toEyeColor(dataIn.readUnsignedByte()); /* +1 = 8 */
    hairColor = dataIn.readUnsignedByte(); /* +1 = 9 */
    featureMask = dataIn.readUnsignedByte(); /* +1 = 10 */
    featureMask = (featureMask << 16) | dataIn.readUnsignedShort(); /* +2 = 12 */
    expression = dataIn.readShort(); /* +2 = 14 */
    poseAngle = new int[3];
    int by = dataIn.readUnsignedByte(); /* +1 = 15 */
    poseAngle[YAW] = by;
    int bp = dataIn.readUnsignedByte(); /* +1 = 16 */
    poseAngle[PITCH] = bp;
    int br = dataIn.readUnsignedByte(); /* +1 = 17 */
    poseAngle[ROLL] = br;
    poseAngleUncertainty = new int[3];
    poseAngleUncertainty[YAW] = dataIn.readUnsignedByte(); /* +1 = 18 */
    poseAngleUncertainty[PITCH] = dataIn.readUnsignedByte(); /* +1 = 19 */
    poseAngleUncertainty[ROLL] = dataIn.readUnsignedByte(); /* +1 = 20 */

    /* Feature Point(s) (optional) (8 * featurePointCount), see ISO 19794-5 5.8 */
    featurePoints = new FeaturePoint[featurePointCount];
    for (int i = 0; i < featurePointCount; i++) {
      int featureType = dataIn.readUnsignedByte(); /* 1 */
      byte featurePoint = dataIn.readByte(); /* +1 = 2 */
      int x = dataIn.readUnsignedShort(); /* +2 = 4 */
      int y = dataIn.readUnsignedShort(); /* +2 = 6 */
      long skippedBytes = 0;
      while (skippedBytes < 2) {
        skippedBytes += dataIn.skip(2);
      } /* +2 = 8, NOTE: 2 bytes reserved */
      featurePoints[i] = new FeaturePoint(featureType, featurePoint, x, y);
    }

    /* Image Information */
    faceImageType = dataIn.readUnsignedByte(); /* 1 */
    imageDataType = dataIn.readUnsignedByte(); /* +1 = 2 */
    setWidth(dataIn.readUnsignedShort()); /* +2 = 4 */
    setHeight(dataIn.readUnsignedShort()); /* +2 = 6 */
    colorSpace = dataIn.readUnsignedByte(); /* +1 = 7 */
    sourceType = dataIn.readUnsignedByte(); /* +1 = 8 */
    deviceType = dataIn.readUnsignedShort(); /* +2 = 10 */
    quality = dataIn.readUnsignedShort(); /* +2 = 12 */

    /* Temporarily fix width and height if 0. */
    if (getWidth() <= 0) {
      setWidth(800);
    }
    if (getHeight() <= 0) {
      setHeight(600);
    }

    /*
     * Read image data, image data type code based on Section 5.8.1
     * ISO 19794-5.
     */
    setMimeType(toMimeType(imageDataType));
    long imageLength = recordLength - 20 - 8 * featurePointCount - 12;

    readImage(inputStream, imageLength);
  }

  /**
   * Writes this face image info to output stream.
   *
   * @param outputStream an output stream
   *
   * @throws IOException if writing fails
   */
  @Override
  public void writeObject(OutputStream outputStream) throws IOException {
    ByteArrayOutputStream recordOut = new ByteArrayOutputStream();
    writeFacialRecordData(recordOut);
    byte[] facialRecordData = recordOut.toByteArray();
    long faceImageBlockLength = facialRecordData.length + 4L;
    DataOutputStream dataOut = new DataOutputStream(outputStream);
    dataOut.writeInt((int)faceImageBlockLength);
    dataOut.write(facialRecordData);
    dataOut.flush();
  }

  /**
   * Returns the record length.
   *
   * @return the record length
   */
  public long getRecordLength() {
    /* Should be equal to (20 + 8 * featurePoints.length + 12 + getImageLength()). */
    return recordLength;
  }

  /**
   * Returns the available feature points of this face.
   *
   * @return feature points
   */
  public FeaturePoint[] getFeaturePoints() {
    return featurePoints;
  }

  /**
   * Returns the expression
   * (neutral, smiling, eyebrow raised, etc).
   *
   * @return expression
   */
  public int getExpression() {
    return expression;
  }

  /**
   * Returns the eye color
   * (black, blue, brown, etc).
   *
   * @return eye color
   */
  public EyeColor getEyeColor() {
    return eyeColor;
  }

  /**
   * Returns the gender
   * (male, female, etc).
   *
   * @return gender
   */
  public Gender getGender() {
    return gender;
  }

  /**
   * Returns the hair color
   * (bald, black, blonde, etc).
   *
   * @return hair color
   */
  public int getHairColor() {
    return hairColor;
  }

  /**
   * Returns the face image type
   * (full frontal, token frontal, etc).
   *
   * @return face image type
   */
  public int getFaceImageType() {
    return faceImageType;
  }

  /**
   * Returns the feature mask.
   *
   * @return feature mask
   */
  public int getFeatureMask() {
    return featureMask;
  }

  /**
   * Returns the quality as unsigned integer.
   *
   * @return quality
   */
  public int getQuality() {
    return quality;
  }

  /**
   * Returns the source type
   * (camera, scanner, etc).
   *
   * @return source type
   */
  public int getSourceType() {
    return sourceType;
  }

  /**
   * Returns the image data type.
   *
   * @return image data type
   */
  public int getImageDataType() {
    return imageDataType;
  }

  /**
   * Returns the image color space
   * (rgb, grayscale, etc).
   *
   * @return image color space
   */
  public int getColorSpace() {
    return colorSpace;
  }

  /**
   * Returns the device type.
   *
   * @return device type
   */
  public int getDeviceType() {
    return deviceType;
  }

  /**
   * Returns the pose angle as an integer array of length 3,
   * containing yaw, pitch, and roll angle in encoded form.
   *
   * @return an integer array of length 3
   */
  public int[] getPoseAngle() {
    int[] result = new int[3];
    System.arraycopy(poseAngle, 0, result, 0, result.length);
    return result;
  }

  /**
   * Returns the pose angle uncertainty as an integer array of length 3,
   * containing yaw, pitch, and roll angle uncertainty.
   *
   * @return an integer array of length 3
   */
  public int[] getPoseAngleUncertainty() {
    int[] result = new int[3];
    System.arraycopy(poseAngleUncertainty, 0, result, 0, result.length);
    return result;
  }

  /**
   * Generates a textual representation of this object.
   *
   * @return a textual representation of this object
   *
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    StringBuilder out = new StringBuilder();
    out.append("FaceImageInfo [");
    out.append("Image size: ").append(getWidth()).append(" x ").append(getHeight()).append(", ");
    out.append("Gender: ").append(gender == null ? Gender.UNSPECIFIED : gender).append(", ");
    out.append("Eye color: ").append(eyeColor == null ? EyeColor.UNSPECIFIED : eyeColor).append(", ");
    out.append("Hair color: ").append(hairColorToString()).append(", ");
    out.append("Feature mask: ").append(featureMaskToString()).append(", ");
    out.append("Expression: ").append(expressionToString()).append(", ");
    out.append("Pose angle: ").append(poseAngleToString()).append(", ");
    out.append("Face image type: ").append(faceImageTypeToString()).append(", ");
    out.append("Source type: ").append(sourceTypeToString()).append(", ");
    out.append("FeaturePoints [");
    if (featurePoints != null && featurePoints.length > 0) {
      boolean isFirstFeaturePoint = true;
      for (FeaturePoint featurePoint: featurePoints) {
        if (isFirstFeaturePoint) {
          isFirstFeaturePoint = false;
        } else {
          out.append(", ");
        }
        out.append(featurePoint.toString());
      }
    }
    out.append("]"); /* FeaturePoints. */
    out.append("]"); /* FaceImageInfo. */
    return out.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + colorSpace;
    result = prime * result + deviceType;
    result = prime * result + expression;
    result = prime * result + ((eyeColor == null) ? 0 : eyeColor.hashCode());
    result = prime * result + faceImageType;
    result = prime * result + featureMask;
    result = prime * result + Arrays.hashCode(featurePoints);
    result = prime * result + ((gender == null) ? 0 : gender.hashCode());
    result = prime * result + hairColor;
    result = prime * result + imageDataType;
    result = prime * result + Arrays.hashCode(poseAngle);
    result = prime * result + Arrays.hashCode(poseAngleUncertainty);
    result = prime * result + quality;
    result = prime * result + (int) (recordLength ^ (recordLength >>> 32));
    result = prime * result + sourceType;
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!super.equals(obj)) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }

    FaceImageInfo other = (FaceImageInfo)obj;
    return colorSpace == other.colorSpace
        && deviceType == other.deviceType
        && expression == other.expression
        && eyeColor == other.eyeColor
        && faceImageType == other.faceImageType
        && featureMask == other.featureMask
        && Arrays.equals(featurePoints, other.featurePoints)
        && gender == other.gender
        && hairColor == other.hairColor
        && imageDataType == other.imageDataType
        && Arrays.equals(poseAngle, other.poseAngle)
        && Arrays.equals(poseAngleUncertainty, other.poseAngleUncertainty)
        && quality == other.quality
        && recordLength == other.recordLength
        && sourceType == other.sourceType;
  }

  /**
   * Writes the record data to a stream.
   *
   * @param outputStream the stream to write to
   *
   * @throws IOException on error
   */
  private void writeFacialRecordData(OutputStream outputStream) throws IOException {
    DataOutputStream dataOut = new DataOutputStream(outputStream);

    /* Facial Information (16) */
    dataOut.writeShort(featurePoints.length);                                              /* 2 */
    dataOut.writeByte(gender == null ? Gender.UNSPECIFIED.toInt() : gender.toInt());       /* 1 */
    dataOut.writeByte(eyeColor == null ? EyeColor.UNSPECIFIED.toInt() : eyeColor.toInt()); /* 1 */
    dataOut.writeByte(hairColor);                                                          /* 1 */
    dataOut.writeByte((byte)((featureMask & 0xFF0000L) >> 16));                            /* 1 */
    dataOut.writeByte((byte)((featureMask & 0x00FF00L) >> 8));                             /* 1 */
    dataOut.writeByte((byte)(featureMask & 0x0000FFL));                                    /* 1 */
    dataOut.writeShort(expression);                                                        /* 2 */
    for (int i = 0; i < 3; i++) {                                                          /* 3 */
      int b = poseAngle[i];
      dataOut.writeByte(b);
    }
    for (int i = 0; i < 3; i++) {                                                          /* 3 */
      dataOut.writeByte(poseAngleUncertainty[i]);
    }

    /* Feature Point(s) (optional) (8 * featurePointCount) */
    for (FeaturePoint fp: featurePoints) {
      dataOut.writeByte(fp.getType());
      dataOut.writeByte((fp.getMajorCode() << 4) | fp.getMinorCode());
      dataOut.writeShort(fp.getX());
      dataOut.writeShort(fp.getY());
      dataOut.writeShort(0x00); /* 2 bytes RFU */
    }

    /* Image Information (12) */
    dataOut.writeByte(faceImageType);                           /* 1 */
    dataOut.writeByte(imageDataType);                           /* 1 */
    dataOut.writeShort(getWidth());                             /* 2 */
    dataOut.writeShort(getHeight());                            /* 2 */
    dataOut.writeByte(colorSpace);                              /* 1 */
    dataOut.writeByte(sourceType);                              /* 1 */
    dataOut.writeShort(deviceType);                             /* 2 */
    dataOut.writeShort(quality);                                /* 2 */

    /*
     * Image data type code based on Section 5.8.1
     * ISO 19794-5
     */
    writeImage(dataOut);
    dataOut.flush();
    dataOut.close();
  }

  /**
   * Converts a hair color value to a human readable string.
   *
   * @return a human readable string for the current hair color value
   */
  private String hairColorToString() {
    switch (hairColor) {
      case HAIR_COLOR_UNSPECIFIED:
        return "unspecified";
      case HAIR_COLOR_BALD:
        return "bald";
      case HAIR_COLOR_BLACK:
        return "black";
      case HAIR_COLOR_BLONDE:
        return "blonde";
      case HAIR_COLOR_BROWN:
        return "brown";
      case HAIR_COLOR_GRAY:
        return "gray";
      case HAIR_COLOR_WHITE:
        return "white";
      case HAIR_COLOR_RED:
        return "red";
      case HAIR_COLOR_GREEN:
        return "green";
      case HAIR_COLOR_BLUE:
        return "blue";
      default:
        return "unknown";
    }
  }

  /**
   * Returns a human readable string for the current feature mask.
   *
   * @return a human readable string
   */
  private String featureMaskToString() {
    if ((featureMask & FEATURE_FEATURES_ARE_SPECIFIED_FLAG) == 0) {
      return "";
    }
    Collection<String> features = new ArrayList<String>();
    if ((featureMask & FEATURE_GLASSES_FLAG) != 0) {
      features.add("glasses");
    }
    if ((featureMask & FEATURE_MOUSTACHE_FLAG) != 0) {
      features.add("moustache");
    }
    if ((featureMask & FEATURE_BEARD_FLAG) != 0) {
      features.add("beard");
    }
    if ((featureMask & FEATURE_TEETH_VISIBLE_FLAG) != 0) {
      features.add("teeth visible");
    }
    if ((featureMask & FEATURE_BLINK_FLAG) != 0) {
      features.add("blink");
    }
    if ((featureMask & FEATURE_MOUTH_OPEN_FLAG) != 0) {
      features.add("mouth open");
    }
    if ((featureMask & FEATURE_LEFT_EYE_PATCH_FLAG) != 0) {
      features.add("left eye patch");
    }
    if ((featureMask & FEATURE_RIGHT_EYE_PATCH) != 0) {
      features.add("right eye patch");
    }
    if ((featureMask & FEATURE_DARK_GLASSES) != 0) {
      features.add("dark glasses");
    }
    if ((featureMask & FEATURE_DISTORTING_MEDICAL_CONDITION) != 0) {
      features.add("distorting medical condition (which could impact feature point detection)");
    }
    StringBuilder out = new StringBuilder();
    for (Iterator<String> it = features.iterator(); it.hasNext();) {
      out.append(it.next());
      if (it.hasNext()) {
        out.append(", ");
      }
    }

    return out.toString();
  }

  /**
   * Converts the current expression to a human readable string.
   *
   * @return a human readable string
   */
  private String expressionToString() {
    switch (expression) {
      case EXPRESSION_UNSPECIFIED:
        return "unspecified";
      case EXPRESSION_NEUTRAL:
        return "neutral (non-smiling) with both eyes open and mouth closed";
      case EXPRESSION_SMILE_CLOSED:
        return "a smile where the inside of the mouth and/or teeth is not exposed (closed jaw)";
      case EXPRESSION_SMILE_OPEN:
        return "a smile where the inside of the mouth and/or teeth is exposed";
      case EXPRESSION_RAISED_EYEBROWS:
        return "raised eyebrows";
      case EXPRESSION_EYES_LOOKING_AWAY:
        return "eyes looking away from the camera";
      case EXPRESSION_SQUINTING:
        return "squinting";
      case EXPRESSION_FROWNING:
        return "frowning";
      default:
        return "unknown";
    }
  }

  /**
   * Converts the current pose angle to a human readable string.
   *
   * @return a human readable string
   */
  private String poseAngleToString() {
    StringBuilder out = new StringBuilder();
    out.append("(");
    out.append("y: ").append(poseAngle[YAW]);
    if (poseAngleUncertainty[YAW] != 0) {
      out.append(" (").append(poseAngleUncertainty[YAW]).append(")");
    }
    out.append(", ");
    out.append("p:").append(poseAngle[PITCH]);
    if (poseAngleUncertainty[PITCH] != 0) {
      out.append(" (").append(poseAngleUncertainty[PITCH]).append(")");
    }
    out.append(", ");
    out.append("r: ").append(poseAngle[ROLL]);
    if (poseAngleUncertainty[ROLL] != 0) {
      out.append(" (").append(poseAngleUncertainty[ROLL]).append(")");
    }
    out.append(")");
    return out.toString();
  }

  /**
   * Returns a textual representation of the face image type
   * ({@code "basic"}, {@code "full frontal"}, {@code "token frontal"},
   * or {@code "unknown"}).
   *
   * @return a textual representation of the face image type
   */
  private String faceImageTypeToString() {
    switch (faceImageType) {
      case FACE_IMAGE_TYPE_BASIC:
        return "basic";
      case FACE_IMAGE_TYPE_FULL_FRONTAL:
        return "full frontal";
      case FACE_IMAGE_TYPE_TOKEN_FRONTAL:
        return "token frontal";
      default:
        return "unknown";
    }
  }

  /**
   * Returns a textual representation of the source type.
   *
   * @return a textual representation of the source type
   */
  private String sourceTypeToString() {
    switch (sourceType) {
      case SOURCE_TYPE_UNSPECIFIED:
        return "unspecified";
      case SOURCE_TYPE_STATIC_PHOTO_UNKNOWN_SOURCE:
        return "static photograph from an unknown source";
      case SOURCE_TYPE_STATIC_PHOTO_DIGITAL_CAM:
        return "static photograph from a digital still-image camera";
      case SOURCE_TYPE_STATIC_PHOTO_SCANNER:
        return "static photograph from a scanner";
      case SOURCE_TYPE_VIDEO_FRAME_UNKNOWN_SOURCE:
        return "single video frame from an unknown source";
      case SOURCE_TYPE_VIDEO_FRAME_ANALOG_CAM:
        return "single video frame from an analogue camera";
      case SOURCE_TYPE_VIDEO_FRAME_DIGITAL_CAM:
        return "single video frame from a digital camera";
      default:
        return "unknown";
    }
  }

  /**
   * Returns a mime-type string for the compression algorithm code.
   *
   * @param compressionAlg the compression algorithm code as it occurs in the header
   *
   * @return a mime-type string,
   *         typically {@code JPEG_MIME_TYPE} or {@code JPEG2000_MIME_TYPE}
   */
  private static String toMimeType(int compressionAlg) {
    switch (compressionAlg) {
      case IMAGE_DATA_TYPE_JPEG:
        return JPEG_MIME_TYPE;
      case IMAGE_DATA_TYPE_JPEG2000:
        return JPEG2000_MIME_TYPE;
      default:
        LOGGER.warning("Unknown image type: " + compressionAlg);
        return null;
    }
  }

  /**
   * Feature points as described in Section 5.6.3 of ISO/IEC FCD 19794-5.
   *
   * @author The JMRTD team (info@jmrtd.org)
   *
   * @version $Revision: 1808 $
   */
  public static class FeaturePoint implements Serializable {

    private static final long serialVersionUID = -4209679423938065215L;

    private int type;
    private int majorCode;
    private int minorCode;
    private int x;
    private int y;

    /**
     * Constructs a new feature point.
     *
     * @param type feature point type
     * @param majorCode major code
     * @param minorCode minor code
     * @param x X-coordinate
     * @param y Y-coordinate
     */
    public FeaturePoint(int type, int majorCode, int minorCode, int x, int y) {
      this.type = type;
      this.majorCode = majorCode;
      this.minorCode = minorCode;
      this.x = x;
      this.y = y;
    }

    /**
     * Constructs a new feature point.
     *
     * @param type feature point type
     * @param code combined major and minor code
     * @param x X-coordinate
     * @param y Y-coordinate
     */
    FeaturePoint(int type, byte code, int x, int y) {
      this(type, (code & 0xF0) >> 4, code & 0x0F, x ,y);
    }

    /**
     * Returns the major code of this point.
     *
     * @return major code
     */
    public int getMajorCode() {
      return majorCode;
    }

    /**
     * Returns the minor code of this point.
     *
     * @return minor code
     */
    public int getMinorCode() {
      return minorCode;
    }

    /**
     * Returns the type of this point.
     *
     * @return type
     */
    public int getType() {
      return type;
    }

    /**
     * Returns the X-coordinate of this point.
     *
     * @return X-coordinate
     */
    public int getX() {
      return x;
    }

    /**
     * Returns the Y-coordinate of this point.
     *
     * @return Y-coordinate
     */
    public int getY() {
      return y;
    }

    /**
     * Generates a textual representation of this point.
     *
     * @return a textual representation of this point
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
      return new StringBuilder()
          .append("( point: ").append(getMajorCode()).append(".").append(getMinorCode())
          .append(", ")
          .append("type: ").append(Integer.toHexString(type)).append(", ")
          .append("(").append(x).append(", ")
          .append(y).append(")")
          .append(")").toString();
    }
  }
}
