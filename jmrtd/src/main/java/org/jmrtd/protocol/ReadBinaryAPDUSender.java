package org.jmrtd.protocol;

import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.APDULevelReadBinaryCapable;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.util.Hex;

/**
 * An APDU sender to support reading binaries. both selection and short file identifier based.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1807 $
 *
 * @since 0.7.0
 */
public class ReadBinaryAPDUSender implements APDULevelReadBinaryCapable {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd.protocol");

  private SecureMessagingAPDUSender secureMessagingSender;

  private CardService service;

  /**
   * Creates an APDU sender.
   *
   * @param service the card service for tranceiving APDUs
   */
  public ReadBinaryAPDUSender(CardService service) {
    this.service = service;
    this.secureMessagingSender = new SecureMessagingAPDUSender(service);
  }

  /**
   * Sends a {@code SELECT APPLET} command to the card.
   *
   * @param wrapper the secure messaging wrapper to use
   * @param aid the applet to select
   *
   * @throws CardServiceException on tranceive error
   */
  public synchronized void sendSelectApplet(APDUWrapper wrapper, byte[] aid) throws CardServiceException {
    if (aid == null) {
      throw new IllegalArgumentException("AID cannot be null");
    }
    CommandAPDU capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT_FILE, (byte) 0x04, (byte) 0x0C, aid);
    ResponseAPDU rapdu = secureMessagingSender.transmit(wrapper, capdu);

    checkStatusWordAfterFileOperation(capdu, rapdu);
  }

  /**
   * Sends a {@code SELECT FILE} command to the passport. Secure
   * messaging will be applied to the command and response apdu.
   *
   * @param wrapper the secure messaging wrapper to use
   * @param fid the file to select
   *
   * @throws CardServiceException on tranceive error
   */
  public synchronized void sendSelectFile(APDUWrapper wrapper, short fid) throws CardServiceException {
    byte[] fiddle = { (byte) ((fid >> 8) & 0xFF), (byte) (fid & 0xFF) };
    CommandAPDU capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT_FILE, (byte) 0x02, (byte) 0x0c, fiddle, 0);
    ResponseAPDU rapdu = secureMessagingSender.transmit(wrapper, capdu);

    if (rapdu == null) {
      return;
    }

    checkStatusWordAfterFileOperation(capdu, rapdu);
  }

  /**
   * Sends a {@code READ BINARY} command to the passport.
   * Secure messaging will be applied to the command and response APDU.
   *
   * @param wrapper the secure messaging wrapper to use, or {@code null} for none
   * @param sfi the short file identifier byte of the file to read as an int value (between 0 and 255)
   *            only if {@code isSFIEnabled} is {@code true}, if not any value)
   * @param offset offset into the file
   *        (either a value between 0 and 255 if {@code isSFIEnabled} is {@code true},
   *        of a value between 0 and 65535 if not)
   * @param le the expected length of the file to read
   * @param isSFIEnabled a boolean indicating whether short file identifiers are used
   * @param isTLVEncodedOffsetNeeded a boolean indicating whether it should be a long ({@code INS == 0xB1}) read
   *
   * @return a byte array of length at most {@code le} with (the specified part of) the contents of the currently selected file
   *
   * @throws CardServiceException if the command was not successful
   */
  public synchronized byte[] sendReadBinary(APDUWrapper wrapper, int sfi, int offset, int le, boolean isSFIEnabled, boolean isTLVEncodedOffsetNeeded) throws CardServiceException {
    CommandAPDU commandAPDU = null;
    ResponseAPDU responseAPDU = null;

    // In case the data ended right on the block boundary
    if (le == 0) {
      return null;
    }

    byte offsetMSB = (byte)((offset & 0xFF00) >> 8);
    byte offsetLSB = (byte)(offset & 0xFF);

    if (isTLVEncodedOffsetNeeded) {
      // In the case of long read 2 or 3 bytes less of the actual data will be returned,
      // because a tag and length will be sent along, here we need to account for this.
      if (le < 128) {
        le += 2;
      } else if (le < 256) {
        le += 3;
      }
      if (le > 256) {
        le = 256;
      }

      byte[] data = new byte[] { 0x54, 0x02, offsetMSB, offsetLSB };
      commandAPDU = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_READ_BINARY2, 0, 0, data, le);
    } else if (isSFIEnabled) {
      commandAPDU = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_READ_BINARY, (byte)sfi, offsetLSB, le);
    } else {
      commandAPDU = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_READ_BINARY, offsetMSB, offsetLSB, le);
    }

    short sw = ISO7816.SW_UNKNOWN;
    try {
      responseAPDU = secureMessagingSender.transmit(wrapper, commandAPDU);
      sw = (short)responseAPDU.getSW();
    } catch (CardServiceException cse) {
      if (service.isConnectionLost(cse)) {
        /*
         * If fatal, we rethrow the underlying exception.
         * If not, we will probably throw an exception later on (in checkStatusWord...).
         * FIXME: Consider not catching this cse at all? -- MO
         */
        throw cse;
      }

      LOGGER.log(Level.FINE, "Exception during READ BINARY", cse);
      sw = (short)cse.getSW();
    }

    byte[] responseData = getResponseData(responseAPDU, isTLVEncodedOffsetNeeded);
    if (responseData == null || responseData.length == 0) {
      LOGGER.warning("Empty response data: rapduBytes = " + Arrays.toString(responseData) + ", le = " + le + ", sw = " + Integer.toHexString(sw));
    } else {
      checkStatusWordAfterFileOperation(commandAPDU, responseAPDU);
    }

    return responseData;
  }

  /* PRIVATE BELOW */

  /**
   * Returns the response data from a response APDU.
   *
   * @param responseAPDU the response APDU
   * @param isTLVEncodedOffsetNeeded whether to expect a {@code 0x53} tag encoded value
   *
   * @return the response data
   *
   * @throws CardServiceException on error
   */
  private static byte[] getResponseData(ResponseAPDU responseAPDU, boolean isTLVEncodedOffsetNeeded) throws CardServiceException {
    if (responseAPDU == null) {
      return null;
    }

    byte[] responseData = responseAPDU.getData();
    if (responseData == null) {
      throw new CardServiceException("Malformed read binary long response data");
    }
    if (!isTLVEncodedOffsetNeeded) {
      return responseData;
    }

    /*
     * Strip the response off the tag 0x53 and the length field.
     * FIXME: Use TLVUtil.tlvEncode(...) here. -- MO
     */
    byte[] data = responseData;
    int index = 0;
    if (data[index++] != (byte)0x53) { // FIXME: Constant for 0x53.
      throw new CardServiceException("Malformed read binary long response data");
    }
    if ((byte)(data[index] & 0x80) == (byte)0x80) {
      index += (data[index] & 0xF);
    }
    index ++;
    responseData = new byte[data.length - index];
    System.arraycopy(data, index, responseData, 0, responseData.length);
    return responseData;
  }

  /**
   * Checks the status word and throws an appropriate {@code CardServiceException} on error.
   *
   * @param commandAPDU the command APDU that was sent
   * @param responseAPDU the response APDU that was received
   *
   * @throws CardServiceException if the response APDU's status word indicates some error
   */
  private static void checkStatusWordAfterFileOperation(CommandAPDU commandAPDU, ResponseAPDU responseAPDU) throws CardServiceException {
    short sw = (short)responseAPDU.getSW();
    String commandResponseMessage = "CAPDU = " + Hex.bytesToHexString(commandAPDU.getBytes()) + ", RAPDU = " + Hex.bytesToHexString(responseAPDU.getBytes());
    switch(sw) {
      case ISO7816.SW_NO_ERROR:
        return;
      case ISO7816.SW_FILE_NOT_FOUND:
        throw new CardServiceException("File not found, " + commandResponseMessage, sw);
      case ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED:
        // Fall through.
      case ISO7816.SW_CONDITIONS_NOT_SATISFIED:
        // Fall through.
      case ISO7816.SW_COMMAND_NOT_ALLOWED:
        throw new CardServiceException("Access to file denied, " + commandResponseMessage, sw);
      default:
        throw new CardServiceException("Error occured, " + commandResponseMessage, sw);
    }
  }
}
