package smartid.hig.no.services;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import net.sourceforge.scuba.smartcards.APDUListener;
import net.sourceforge.scuba.smartcards.CardService;
import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.smartcards.ISO7816;
import net.sourceforge.scuba.util.Hex;

import smartid.hig.no.utils.CryptoUtils;

/**
 * Low level card service for sending apdus to the card. This service is not
 * responsible for maintaining information about the state of the authentication
 * or secure messaging protocols. It merely offers the basic functionality for
 * sending specific apdus to the card.
 *
 * Based on ICAO-TR-PKI. Defines the following commands:
 * <ul>
 * <li><code>GET CHALLENGE</code> (also using secure messaging for EAC)</li>
 * <li><code>EXTERNAL AUTHENTICATE</code> (also using secure messaging for
 * EAC)</li>
 * <li><code>INTERNAL AUTHENTICATE</code> (using secure messaging)</li>
 * <li><code>MANAGE SECURE ENVIRONMENT</code> (for EAC)</li>
 * <li><code>PERFORM SECURITY OPERATION</code> (for EAC)</li>
 * <li><code>SELECT FILE</code> (using secure messaging)</li>
 * <li><code>READ BINARY</code> (using secure messaging)</li>
 * </ul>
 *
 *
 */
public class ApduService extends CardService {

	private static final long serialVersionUID = -7938380948364076484L;

	/**
	 * The applet we select when we start a session.
	 */
	private static final byte[] APPLET_AID = {(byte) 0x20, 0x14, 0x06, 0x01,
		0x00, 0x00, 0x01};

	/**
	 * Initialization vector used by the cipher below.
	 */
	private static final IvParameterSpec ZERO_IV_PARAM_SPEC = new IvParameterSpec(
			new byte[8]);

	/**
	 * The service we decorate.
	 */
	private CardService service;

	/**
	 * DESede encryption/decryption cipher.
	 */
	private Cipher cipher;

	/**
	 * ISO9797Alg3Mac.
	 */
	private Mac mac;

	/**
	 * Creates a new passwd manager apdu sending service.
	 *
	 * @param service another service which will deal with sending the apdus to
	 * the card
	 *
	 * @throws GeneralSecurityException when the available JCE providers cannot
	 * provide the necessary cryptographic primitives:
	 * <ul>
	 * <li>Cipher: "DESede/CBC/Nopadding"</li>
	 * <li>Mac: "ISO9797Alg3Mac"</li>
	 * </ul>
	 */
	public ApduService(CardService service)
			throws CardServiceException {
		this.service = service;
		try {
			cipher = Cipher.getInstance("DESede/CBC/NoPadding");
			mac = Mac.getInstance("ISO9797Alg3Mac");
		} catch (GeneralSecurityException gse) {
			throw new CardServiceException(gse.toString());
		}
	}

	/**
	 * Opens a session by connecting to the card and selecting the applet.
	 */
	public void open() throws CardServiceException {
		if (!service.isOpen()) {
			service.open();
		}
		sendSelectApplet();
	}

	public synchronized boolean isOpen() {
		return service.isOpen();
	}

	public void setListenersState(boolean state) {
		service.setListenersState(state);
	}

	private void sendSelectApplet() throws CardServiceException {
		int sw = sendSelectApplet(APPLET_AID);
		if (sw != 0x00009000) {
			throw new CardServiceException("Could not select driving license");
		}
	}

	public synchronized ResponseAPDU transmit(CommandAPDU capdu)
			throws CardServiceException {
		return service.transmit(capdu);
	}

	public void close() {
		if (service != null) {
			service.close();
		}
	}

	public void setService(CardService service) {
		this.service = service;
	}

	public void addAPDUListener(APDUListener l) {
		service.addAPDUListener(l);
	}

	public void removeAPDUListener(APDUListener l) {
		service.removeAPDUListener(l);
	}

	CommandAPDU createSelectAppletAPDU(byte[] aid) {
		byte[] data = aid;
		CommandAPDU apdu = new CommandAPDU(ISO7816.CLA_ISO7816,
				ISO7816.INS_SELECT_FILE, (byte) 0x04, (byte) 0x00, data,
				(byte) 0x01);
		return apdu;
	}

	CommandAPDU createSelectFileAPDU(short fid) {
		byte[] fiddle = {(byte) ((fid >> 8) & 0x000000FF),
			(byte) (fid & 0x000000FF)};
		return createSelectFileAPDU(fiddle);
	}

	private CommandAPDU createSelectFileAPDU(byte[] fid) {
		CommandAPDU apdu = new CommandAPDU(ISO7816.CLA_ISO7816,
				ISO7816.INS_SELECT_FILE, (byte) 0x02, (byte) 0x0c, fid, 256);
		return apdu;
	}

	CommandAPDU createReadBinaryAPDU(short offset, int le) {
		byte p1 = (byte) ((offset & 0x0000FF00) >> 8);
		byte p2 = (byte) (offset & 0x000000FF);
		CommandAPDU apdu = new CommandAPDU(ISO7816.CLA_ISO7816,
				ISO7816.INS_READ_BINARY, p1, p2, le);
		return apdu;
	}

	CommandAPDU createGetChallengeAPDU(int le) {
		byte p1 = (byte) 0x00;
		byte p2 = (byte) 0x00;
		CommandAPDU apdu = new CommandAPDU(ISO7816.CLA_ISO7816,
				ISO7816.INS_GET_CHALLENGE, p1, p2, le);
		return apdu;
	}

	CommandAPDU createInternalAuthenticateAPDU(byte[] rndIFD) {
		if (rndIFD == null || rndIFD.length != 8) {
			throw new IllegalArgumentException("rndIFD wrong length");
		}
		byte p1 = (byte) 0x00;
		byte p2 = (byte) 0x00;
		byte[] data = rndIFD;
		int le = 255; /* whatever... */

		CommandAPDU apdu = new CommandAPDU(ISO7816.CLA_ISO7816,
				ISO7816.INS_INTERNAL_AUTHENTICATE, p1, p2, data, le);
		return apdu;
	}

	/**
	 * Creates an <code>EXTERNAL AUTHENTICATE</code> command.
	 *
	 * @param rndIFD our challenge
	 * @param rndICC their challenge
	 * @param kIFD our key material
	 * @param kEnc the static encryption key
	 * @param kMac the static mac key
	 *
	 * @return the apdu to be sent to the card.
	 */
	CommandAPDU createMutualAuthAPDU(byte[] rndIFD, byte[] rndICC, byte[] kIFD,
			SecretKey kEnc, SecretKey kMac) throws GeneralSecurityException {
		if (rndIFD == null || rndIFD.length != 8) {
			throw new IllegalArgumentException("rndIFD wrong length");
		}
		if (rndICC == null || rndICC.length != 8) {
			// throw new IllegalArgumentException("rndICC wrong length");
			rndICC = new byte[8];
		}
		if (kIFD == null || kIFD.length != 16) {
			throw new IllegalArgumentException("kIFD wrong length");
		}
		if (kEnc == null) {
			throw new IllegalArgumentException("kEnc == null");
		}
		if (kMac == null) {
			throw new IllegalArgumentException("kMac == null");
		}

		cipher.init(Cipher.ENCRYPT_MODE, kEnc, ZERO_IV_PARAM_SPEC);
		/*
		 * cipher.update(rndIFD); cipher.update(rndICC); cipher.update(kIFD); //
		 * This doesn't work, apparently we need to create plaintext array. //
		 * Probably has something to do with ZERO_IV_PARAM_SPEC.
		 */
		byte[] plaintext = new byte[32];
		System.arraycopy(rndIFD, 0, plaintext, 0, 8);
		System.arraycopy(rndICC, 0, plaintext, 8, 8);
		System.arraycopy(kIFD, 0, plaintext, 16, 16);
		byte[] ciphertext = cipher.doFinal(plaintext);
		if (ciphertext.length != 32) {
			throw new IllegalStateException("Cryptogram wrong length "
					+ ciphertext.length);
		}

		mac.init(kMac);
		byte[] mactext = mac.doFinal(CryptoUtils.pad(ciphertext));
		if (mactext.length != 8) {
			throw new IllegalStateException("MAC wrong length");
		}

		byte p1 = (byte) 0x00;
		byte p2 = (byte) 0x00;

		byte[] data = new byte[32 + 8];
		System.arraycopy(ciphertext, 0, data, 0, 32);
		System.arraycopy(mactext, 0, data, 32, 8);
		int le = 40;
		CommandAPDU apdu = new CommandAPDU(ISO7816.CLA_ISO7816,
				ISO7816.INS_EXTERNAL_AUTHENTICATE, p1, p2, data, le);
		return apdu;
	}

	/**
	 * Creates the EXTERNAL AUTHENTICATE command for EAC.
	 *
	 * @param signature the challange signed by the terminal
	 * @return command APDU
	 */
	CommandAPDU createMutualAuthAPDU(byte[] signature) {
		return new CommandAPDU(ISO7816.CLA_ISO7816,
				ISO7816.INS_EXTERNAL_AUTHENTICATE, 0, 0, signature);
	}

	/**
	 * Create (possibly chained) APDU for PSO verify certificate (p2 = 0xBE)
	 *
	 * @param certData certificate data
	 * @param offset offset to certificate data
	 * @param length length of the data to send
	 * @param last whether this is the last APDU in chain
	 * @return command APDU
	 */
	CommandAPDU createPSOAPDU(byte[] certData, int offset, int length,
			boolean last) {
		byte p1 = (byte) 0x00;
		byte p2 = (byte) 0xBE;
		byte[] data = new byte[length];
		System.arraycopy(certData, offset, data, 0, length);
		CommandAPDU apdu = new CommandAPDU(ISO7816.CLA_ISO7816
				| (last ? 0x00 : 0x10), ISO7816.INS_PSO, p1, p2, data);
		return apdu;
	}

	/**
	 * Sends a <code>PSO</code> command to the card.
	 *
	 * @param certificate data to be verified
	 *
	 * @return status word
	 */
	public synchronized void sendPSO(SecureMessagingWrapper wrapper,
			byte[] certData) throws CardServiceException {
		int maxBlock = 223;
		int blockSize = 223;
		int offset = 0;
		int length = certData.length;
		if (certData.length > maxBlock) {
			int numBlock = certData.length / blockSize;
			if (numBlock * blockSize < certData.length) {
				numBlock++;
			}
			int i = 0;
			while (i < numBlock - 1) {
				CommandAPDU c = createPSOAPDU(certData, offset, blockSize,
						false);
				if (wrapper != null) {
					c = wrapper.wrap(c);
				}
				ResponseAPDU r = transmit(c);
				if (wrapper != null) {
					r = wrapper.unwrap(r, r.getBytes().length);
				}
				int sw = r.getSW();
				if ((short) sw != ISO7816.SW_NO_ERROR) {
					throw new CardServiceException("Sending PSO failed.");
				}
				length -= blockSize;
				offset += blockSize;
				i++;
			}
		}
		CommandAPDU c = createPSOAPDU(certData, offset, length, true);
		if (wrapper != null) {
			c = wrapper.wrap(c);
		}
		ResponseAPDU r = transmit(c);
		if (wrapper != null) {
			r = wrapper.unwrap(r, r.getBytes().length);
		}
		int sw = r.getSW();
		if ((short) sw != ISO7816.SW_NO_ERROR) {
			throw new CardServiceException("Sending PSO failed.");
		}
	}

	/**
	 * Sends the MSE apdu to the CARD.
	 *
	 * @param wrapper secure messaging wrapper
	 * @param p1 p1 value
	 * @param p2 p2 value
	 * @param data data to be send
	 * @throws CardServiceException if the resulting status word different from
	 * 9000
	 */
	public synchronized void sendMSE(SecureMessagingWrapper wrapper, int p1,
			int p2, byte[] data) throws CardServiceException {
		CommandAPDU c = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_MSE,
				p1, p2, data);
		if (wrapper != null) {
			c = wrapper.wrap(c);
		}
		ResponseAPDU r = transmit(c);
		if (wrapper != null) {
			r = wrapper.unwrap(r, r.getBytes().length);
		}
		int sw = r.getSW();
		if ((short) sw != ISO7816.SW_NO_ERROR) {
			throw new CardServiceException("Sending MSE failed.");
		}
	}

	/**
	 * Sends the EXTERNAL AUTHENTICATE commands for EAC terminal verification
	 *
	 * @param wrapper secure messaging wrapper
	 * @param signature terminal signature
	 * @throws CardServiceException if the resulting status word different from
	 * 9000
	 */
	public synchronized void sendMutualAuthenticate(
			SecureMessagingWrapper wrapper, byte[] signature)
			throws CardServiceException {
		CommandAPDU c = createMutualAuthAPDU(signature);
		if (wrapper != null) {
			c = wrapper.wrap(c);
		}
		ResponseAPDU r = transmit(c);
		if (wrapper != null) {
			r = wrapper.unwrap(r, r.getBytes().length);
		}
		int sw = r.getSW();
		if ((short) sw != ISO7816.SW_NO_ERROR) {
			throw new CardServiceException(
					"Sending External Authenticate failed.");
		}
	}

	/**
	 * Sends a <code>SELECT APPLET</code> command to the card.
	 *
	 * @param aid the applet to select
	 *
	 * @return status word
	 */
	public synchronized int sendSelectApplet(byte[] aid)
			throws CardServiceException {
		return transmit(createSelectAppletAPDU(aid)).getSW();
	}

	/**
	 * Sends a <code>SELECT FILE</code> command to the CARD. Secure messaging
	 * will be applied to the command and response apdu.
	 *
	 * @param wrapper the secure messaging wrapper to use
	 * @param fid the file to select
	 */
	public synchronized void sendSelectFile(SecureMessagingWrapper wrapper,
			short fid) throws CardServiceException {
		CommandAPDU capdu = createSelectFileAPDU(fid);
		if (wrapper != null) {
			capdu = wrapper.wrap(capdu);
		}
		ResponseAPDU rapdu = transmit(capdu);
		if (wrapper != null) {
			rapdu = wrapper.unwrap(rapdu, rapdu.getBytes().length);
		}
		short sw = (short) rapdu.getSW();
		if (sw == ISO7816.SW_FILE_NOT_FOUND) {
			throw new CardServiceException("File not found.");
		}
		if (sw != ISO7816.SW_NO_ERROR) {
			throw new CardServiceException("Error occured.");
		}
	}

	/**
	 * Sends a <code>READ BINARY</code> command to the CARD.
	 *
	 * @param offset offset into the file
	 * @param le the expected length of the file to read
	 *
	 * @return a byte array of length <code>le</code> with (the specified part
	 * of) the contents of the currently selected file
	 */
	public synchronized byte[] sendReadBinary(short offset, int le)
			throws CardServiceException {
		return sendReadBinary(null, offset, le);
	}

	/**
	 * Sends a <code>READ BINARY</code> command to the card. Secure messaging
	 * will be applied to the command and response apdu.
	 *
	 * @param wrapper the secure messaging wrapper to use
	 * @param offset offset into the file
	 * @param le the expected length of the file to read
	 *
	 * @return a byte array of length <code>le</code> with (the specified part
	 * of) the contents of the currently selected file
	 */
	public synchronized byte[] sendReadBinary(SecureMessagingWrapper wrapper,
			short offset, int le) throws CardServiceException {
		boolean repeatOnEOF = false;
		ResponseAPDU rapdu = null;
		do {
			repeatOnEOF = false;
			// In case the data ended right on the block boundary
			if (le == 0) {
				return null;
			}
			CommandAPDU capdu = createReadBinaryAPDU(offset, le);
			if (wrapper != null) {
				capdu = wrapper.wrap(capdu);
			}
			rapdu = transmit(capdu);
			if (wrapper != null) {
				rapdu = wrapper.unwrap(rapdu, rapdu.getBytes().length);
			}
			if (rapdu.getSW() == ISO7816.SW_END_OF_FILE) {
				le--;
				repeatOnEOF = true;
			}
		} while (repeatOnEOF);
		return rapdu.getData();
	}

	/**
	 * Sends a <code>GET CHALLENGE</code> command to the card. Possibly use
	 * secure messaging (EAC).
	 *
	 * @return a byte array of length 8 containing the challenge
	 */
	public synchronized byte[] sendGetChallenge(SecureMessagingWrapper wrapper)
			throws CardServiceException {
		CommandAPDU capdu = createGetChallengeAPDU(8);
		if (wrapper != null) {
			capdu = wrapper.wrap(capdu);
		}
		ResponseAPDU rapdu = transmit(capdu);
		if (wrapper != null) {
			rapdu = wrapper.unwrap(rapdu, rapdu.getBytes().length);
		}
		return rapdu.getData();
	}

	/**
	 * Sends an <code>INTERNAL AUTHENTICATE</code> command to the card.
	 *
	 * @param wrapper secure messaging wrapper
	 * @param rndIFD the challenge to send
	 *
	 * @return the response from the card (status word removed)
	 */
	public synchronized byte[] sendInternalAuthenticate(
			SecureMessagingWrapper wrapper, byte[] rndIFD)
			throws CardServiceException {
		CommandAPDU capdu = createInternalAuthenticateAPDU(rndIFD);
		if (wrapper != null) {
			capdu = wrapper.wrap(capdu);
		}
		ResponseAPDU rapdu = transmit(capdu);
		if (wrapper != null) {
			rapdu = wrapper.unwrap(rapdu, rapdu.getBytes().length);
		}
		return rapdu.getData();
	}

	/**
	 * Sends an <code>EXTERNAL AUTHENTICATE</code> command to the card. The
	 * resulting byte array has length 32 and contains <code>rndICC</code>
	 * (first 8 bytes), <code>rndIFD</code> (next 8 bytes), their key material
	 * "<code>kICC</code>" (last 16 bytes).
	 *
	 * @param rndIFD our challenge
	 * @param rndICC their challenge
	 * @param kIFD our key material
	 * @param kEnc the static encryption key
	 * @param kMac the static mac key
	 *
	 * @return a byte array of length 32 containing the response that was sent
	 * by the card, decrypted (using <code>kEnc</code>) and verified (using
	 * <code>kMac</code>)
	 */
	public synchronized byte[] sendMutualAuth(byte[] rndIFD, byte[] rndICC,
			byte[] kIFD, SecretKey kEnc, SecretKey kMac)
			throws CardServiceException {
		try {
			ResponseAPDU rapdu = transmit(createMutualAuthAPDU(rndIFD, rndICC,
					kIFD, kEnc, kMac));
			byte[] rapduBytes = rapdu.getBytes();
			if (rapduBytes == null) {
				throw new CardServiceException("Mutual authentication failed");
			}
			String errorCode = Hex.shortToHexString((short) rapdu.getSW());
			if (rapduBytes.length == 2) {
				throw new CardServiceException(
						"Mutual authentication failed: error code:  "
						+ errorCode);
			}

			if (rapduBytes.length != 42) {
				throw new CardServiceException(
						"Mutual authentication failed: expected length: 42, actual length: "
						+ rapduBytes.length + ", error code: "
						+ errorCode);
			}

			/* Decrypt the response. */
			cipher.init(Cipher.DECRYPT_MODE, kEnc, ZERO_IV_PARAM_SPEC);
			byte[] result = cipher.doFinal(rapduBytes, 0,
					rapduBytes.length - 8 - 2);
			if (result.length != 32) {
				throw new IllegalStateException("Cryptogram wrong length "
						+ result.length);
			}
			return result;
		} catch (GeneralSecurityException gse) {
			throw new CardServiceException(gse.toString());
		}
	}

	public CardService getService() {
		return service;
	}
}
