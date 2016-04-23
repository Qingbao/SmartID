package smartid.hig.no.services;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.ejbca.cvc.CVCertificate;

import net.sourceforge.scuba.smartcards.CardService;
import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.smartcards.ISO7816;
import net.sourceforge.scuba.tlv.BERTLVObject;

/**
 * Service for initializing blank applets.
 *
 */
public class PersoService extends CardService {

	private static final long serialVersionUID = -2054600604861470052L;

	private static final byte INS_PUT_DATA = (byte) 0xda;
	;

    private static final byte PRIVMODULUS_TAG = 0x60;

	private static final byte PRIVEXPONENT_TAG = 0x61;

	private static final byte KEYDOC_TAG = 0x62;

	private static final byte ECPRIVATE_TAG = 0x63;

	private static final byte CVCERTIFICATE_TAG = 0x64;

	private static final byte SICID_TAG = 0x65;

	public static final boolean ECFP = true;

	/**
	 * The name of the EC curve for DH key pair generation.
	 */
	public static final String EC_CURVE_NAME = ECFP ? "prime192v1" : "c2pnb163v1";

	private BasicService service;

	/**
	 * Constructs a new personalization service.
	 *
	 * @param service card service to use
	 * @throws CardServiceException
	 */
	public PersoService(CardService service)
			throws CardServiceException {
		this.service = (service instanceof BasicService) ? (BasicService) service
				: new BasicService(service);
	}

	private byte[] putData(byte p1, byte p2, byte[] data)
			throws CardServiceException {
		CommandAPDU capdu = new CommandAPDU(0, INS_PUT_DATA, p1, p2, data);
		SecureMessagingWrapper wrapper = service.getWrapper();

		if (wrapper != null) {
			capdu = wrapper.wrap(capdu);
		}
		ResponseAPDU rapdu = service.transmit(capdu);
		if (wrapper != null) {
			rapdu = wrapper.unwrap(rapdu, rapdu.getBytes().length);
		}
		return rapdu.getData();
	}

	/**
	 * Sends a PUT_DATA command to the card to set the private key used for
	 * Active Authentication.
	 *
	 * @param key holding the private key data.
	 * @throws CardServiceException on error.
	 */
	public void putPrivateKey(PrivateKey key) throws CardServiceException {
		try {
			byte[] encodedPriv = key.getEncoded();
			BERTLVObject encodedPrivObject = BERTLVObject
					.getInstance(new ByteArrayInputStream(encodedPriv));
			byte[] privKeyData = (byte[]) encodedPrivObject.getChildByIndex(2)
					.getValue();
			BERTLVObject privKeyDataObject = BERTLVObject
					.getInstance(new ByteArrayInputStream(privKeyData));
			byte[] privModulus = (byte[]) privKeyDataObject.getChildByIndex(1)
					.getValue();
			byte[] privExponent = (byte[]) privKeyDataObject.getChildByIndex(3)
					.getValue();

			putPrivateKey(privModulus, privExponent);
		} catch (IOException ioe) {
			throw new CardServiceException(ioe.toString());
		} catch (Exception pe) {
			throw new CardServiceException(pe.toString());
		}
	}

	private void putPrivateKey(byte[] privModulus, byte[] privExponent)
			throws CardServiceException {
		try {
			BERTLVObject privModulusObject = new BERTLVObject(PRIVMODULUS_TAG,
					new BERTLVObject(BERTLVObject.OCTET_STRING_TYPE_TAG,
							privModulus));

			putData((byte) 0, PRIVMODULUS_TAG, privModulusObject.getEncoded());

			BERTLVObject privExponentObject = new BERTLVObject(
					PRIVEXPONENT_TAG, new BERTLVObject(
							BERTLVObject.OCTET_STRING_TYPE_TAG, privExponent));

			putData((byte) 0, PRIVEXPONENT_TAG, privExponentObject.getEncoded());
		} catch (Exception ioe) {
			throw new CardServiceException(ioe.toString());
		}
	}

	/**
	 * Sends a PUT_DATA command to the card to set the private key used for
	 * Extended Access Control.
	 *
	 * @param privateKey holding the private key data.
	 * @throws CardServiceException on error.
	 */
	public void putPrivateEACKey(ECPrivateKey privateKey)
			throws CardServiceException {

		byte[] aArray = privateKey.getParams().getCurve().getA().toByteArray();
		byte[] bArray = privateKey.getParams().getCurve().getB().toByteArray();

		byte[] rArray = privateKey.getParams().getOrder().toByteArray();
		short k = (short) privateKey.getParams().getCofactor();

		byte[] kArray = new byte[2];
		kArray[0] = (byte) ((k & 0xFF00) >> 8);
		kArray[1] = (byte) (k & 0xFF);

		byte[] pArray = null;
		if (ECFP) {
			ECFieldFp fp = (ECFieldFp) privateKey.getParams().getCurve().getField();
			pArray = new byte[fp.getFieldSize()];
			pArray = fp.getP().toByteArray();
		} else {
			ECFieldF2m fm = (ECFieldF2m) privateKey.getParams().getCurve()
					.getField();
			if (fm.getMidTermsOfReductionPolynomial() == null) {
				int m = fm.getM();
				pArray = new byte[2];
				pArray[0] = (byte) ((m & 0xFF00) >> 8);
				pArray[1] = (byte) (m & 0xFF);
			} else {
				int[] ms = fm.getMidTermsOfReductionPolynomial();
				int off = 0;
				pArray = new byte[ms.length * 2];
				for (int i = 0; i < ms.length; i++) {
					int m = ms[i];
					pArray[off + 0] = (byte) ((m & 0xFF00) >> 8);
					pArray[off + 1] = (byte) (m & 0xFF);
					off += 2;
				}
			}
		}

		org.bouncycastle.jce.interfaces.ECPrivateKey ktmp = (org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey;
		org.bouncycastle.math.ec.ECPoint point = ktmp.getParameters().getG();
		byte[] gArray = point.getEncoded();
		byte[] sArray = privateKey.getS().toByteArray();
		pArray = BasicService.tagData((byte) 0x81, pArray);
		aArray = BasicService.tagData((byte) 0x82, aArray);
		bArray = BasicService.tagData((byte) 0x83, bArray);
		gArray = BasicService.tagData((byte) 0x84, gArray);
		rArray = BasicService.tagData((byte) 0x85, rArray);
		sArray = BasicService.tagData((byte) 0x86, sArray);
		kArray = BasicService.tagData((byte) 0x87, kArray);

		int offset = 0;
		byte[] all = new byte[pArray.length + aArray.length + bArray.length
				+ gArray.length + rArray.length + sArray.length + kArray.length];
		System.arraycopy(pArray, 0, all, offset, pArray.length);
		offset += pArray.length;
		System.arraycopy(aArray, 0, all, offset, aArray.length);
		offset += aArray.length;
		System.arraycopy(bArray, 0, all, offset, bArray.length);
		offset += bArray.length;
		System.arraycopy(gArray, 0, all, offset, gArray.length);
		offset += gArray.length;
		System.arraycopy(rArray, 0, all, offset, rArray.length);
		offset += rArray.length;
		System.arraycopy(sArray, 0, all, offset, sArray.length);
		offset += sArray.length;
		System.arraycopy(kArray, 0, all, offset, kArray.length);
		offset += kArray.length;

		putData((byte) 0, ECPRIVATE_TAG, all);
	}

	/**
	 * Sends a PUT_DATA command to the card to set the root cv certificate for
	 * Extended Access Control.
	 *
	 * @param certificate card verifiable certificate
	 * @throws CardServiceException on error.
	 */
	public void putCVCertificate(CVCertificate certificate)
			throws CardServiceException {
		try {
			putData((byte) 0, CVCERTIFICATE_TAG, certificate
					.getCertificateBody().getDEREncoded());
		} catch (Exception e) {
			throw new CardServiceException(e.toString());
		}
	}

	/**
	 * Sends a PUT_DATA command to the card to set the SIC ID number for
	 * Extended Access Control.
	 *
	 * @param sicId SIC ID number
	 * @throws CardServiceException on error.
	 */
	public void setSicId(String sicId) throws CardServiceException {
		try {
			putData((byte) 0, SICID_TAG, sicId.getBytes());
		} catch (Exception e) {
			throw new CardServiceException(e.toString());
		}
	}

	/**
	 * *************************************************************************
	 * Sends a CREATE_FILE APDU to the card.
	 *
	 * @param fid (file identifier) of the new file.
	 * @param length of the new file.
	 */
	public void createFile(short fid, short length) throws CardServiceException {
		sendCreateFile(service.getWrapper(), fid, length, false);
	}

	/**
	 * *************************************************************************
	 * Sends a CREATE_FILE APDU to the card.
	 *
	 * @param fid (file identifier) of the new file.
	 * @param length of the new file.
	 * @param eapProtection whether the file should be EAC protected
	 */
	public void createFile(short fid, short length, boolean eapProtection)
			throws CardServiceException {
		sendCreateFile(service.getWrapper(), fid, length, eapProtection);
	}

	private CommandAPDU createCreateFileAPDU(short fid, short length,
			boolean eapProtection) {
		byte p1 = eapProtection ? (byte) 0x01 : (byte) 0x00;
		byte p2 = (byte) 0x00;
		int le = 0;
		byte[] data = {0x63, 4, (byte) ((length >>> 8) & 0xff),
			(byte) (length & 0xff), (byte) ((fid >>> 8) & 0xff),
			(byte) (fid & 0xff)};
		CommandAPDU apdu = new CommandAPDU(ISO7816.CLA_ISO7816,
				ISO7816.INS_CREATE_FILE, p1, p2, data, le);
		return apdu;
	}

	private byte[] sendCreateFile(SecureMessagingWrapper wrapper, short fid,
			short length, boolean eapProtection) throws CardServiceException {
		CommandAPDU capdu = createCreateFileAPDU(fid, length, eapProtection);
		if (wrapper != null) {
			capdu = wrapper.wrap(capdu);
		}
		ResponseAPDU rapdu = service.transmit(capdu);
		if (wrapper != null) {
			rapdu = wrapper.unwrap(rapdu, rapdu.getBytes().length);
		}
		return rapdu.getData();
	}

	private CommandAPDU createUpdateBinaryAPDU(short offset, int data_len,
			byte[] data) {
		byte p1 = (byte) ((offset >>> 8) & 0xff);
		byte p2 = (byte) (offset & 0xff);
		byte[] chunk = new byte[data_len];
		System.arraycopy(data, 0, chunk, 0, data_len);
		CommandAPDU apdu = new CommandAPDU(ISO7816.CLA_ISO7816,
				ISO7816.INS_UPDATE_BINARY, p1, p2, chunk);
		return apdu;
	}

	private byte[] sendUpdateBinary(SecureMessagingWrapper wrapper,
			short offset, int data_len, byte[] data)
			throws CardServiceException {
		CommandAPDU capdu = createUpdateBinaryAPDU(offset, data_len, data);
		if (wrapper != null) {
			capdu = wrapper.wrap(capdu);
		}
		ResponseAPDU rapdu = service.transmit(capdu);
		if (wrapper != null) {
			rapdu = wrapper.unwrap(rapdu, rapdu.getBytes().length);
		}
		return rapdu.getData();

	}

	/**
	 * Writes a DataGroup in the card
	 *
	 * @param fid the fid of the file to write
	 * @param in the inputstream of the file to write
	 * @throws CardServiceException on error
	 */
	public void writeFile(short fid, InputStream in)
			throws CardServiceException {
		SecureMessagingWrapper wrapper = service.getWrapper();
		try {
			int length = 0xff;
			if (wrapper != null) {
				length -= 32;
			}
			byte[] data = new byte[length];

			int r = 0;
			short offset = 0;
			while (true) {
				r = in.read(data, (short) 0, data.length);
				if (r == -1) {
					break;
				}
				sendUpdateBinary(wrapper, offset, r, data);
				offset += r;
			}
		} catch (IOException ioe) {
			throw new CardServiceException(ioe.toString());
		}
	}

	/**
	 * Initiates the card with key seed string (SAI string)
	 *
	 * @throws CardServiceException on error
	 */
	public void setBAC(byte[] keySeed) throws CardServiceException {
		if (keySeed.length < 16) {
			throw new IllegalStateException("Key seed too short");
		}
		try {
			putData((byte) 0, KEYDOC_TAG, keySeed);
		} catch (Exception ioe) {
			throw new CardServiceException(ioe.toString());
		}
	}

	/**
	 * Locks the applet so that no data may be written to it.
	 *
	 * @throws CardServiceException on error.
	 */
	public void lockApplet() throws CardServiceException {
		putData((byte) 0xde, (byte) 0xad, null);
	}

	/**
	 * Selects a file on the applet.
	 *
	 * @param fid the file ID to select
	 * @throws CardServiceException on error.
	 */
	public void selectFile(short fid) throws CardServiceException {
		service.sendSelectFile(service.getWrapper(), fid);
	}

	public void close() {
		service.close();
	}

	public boolean isOpen() {
		return service.isOpen();
	}

	public void open() throws CardServiceException {
		service.open();
	}

	public ResponseAPDU transmit(CommandAPDU apdu) throws CardServiceException {
		return service.transmit(apdu);
	}
}
