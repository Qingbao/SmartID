/**
 *
 */
package smartid.hig.no.services;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;

import org.ejbca.cvc.AlgorithmUtil;
import org.ejbca.cvc.CVCertificate;

import smartid.hig.no.events.AAEvent;
import smartid.hig.no.events.BACEvent;
import smartid.hig.no.events.EACEvent;
import smartid.hig.no.lds.FileStructure;
import smartid.hig.no.utils.CryptoUtils;

import net.sourceforge.scuba.smartcards.CardFileInputStream;
import net.sourceforge.scuba.smartcards.CardService;
import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.smartcards.FileInfo;
import net.sourceforge.scuba.smartcards.FileSystemStructured;
import net.sourceforge.scuba.tlv.BERTLVInputStream;

/**
 * Card service for reading datagroups and using the BAC, AA, and EAC protocols
 * on the card. Defines secure messaging (BAC). Defines Extended Access Control.
 * Defines Active Authentication.
 *
 *
 *
 *
 */
public class BasicService extends ApduService {

	private static final long serialVersionUID = 5492868446003453613L;

	public static final short EF_DG1 = 0x0001;

	public static final byte SF_DG1 = 0x01;

	public static final short EF_DG2 = 0x0002;

	public static final byte SF_DG2 = 0x02;

	public static final short EF_DG3 = 0x0003;

	public static final byte SF_DG3 = 0x03;

	public static final short EF_DG4 = 0x0004;

	public static final byte SF_DG4 = 0x04;

	public static final short EF_DG5 = 0x0005;

	public static final byte SF_DG5 = 0x05;

	public static final short EF_DG6 = 0x0006;

	public static final byte SF_DG6 = 0x06;

	public static final short EF_DG7 = 0x0007;

	public static final byte SF_DG7 = 0x07;

	public static final short EF_DG8 = 0x0008;

	public static final byte SF_DG8 = 0x08;

	public static final short EF_DG9 = 0x0009;

	public static final byte SF_DG9 = 0x09;

	public static final short EF_DG10 = 0x000A;

	public static final byte SF_DG10 = 0x0A;

	public static final short EF_DG11 = 0x000B;

	public static final byte SF_DG11 = 0x0B;

	public static final short EF_DG12 = 0x000C;

	public static final byte SF_DG12 = 0x0C;

	public static final short EF_DG13 = 0x000D;

	public static final byte SF_DG13 = 0x0D;

	/**
	 * Data group 14 contains extended access control (EAC) public key.
	 */
	public static final short EF_DG14 = 0x000E;

	public static final byte SF_DG14 = 0x0E;

	/**
	 * Data group 15 contains active authentication (AA) certificate.
	 */
	public static final short EF_DG15 = 0x000F;

	public static final byte SF_DG15 = 0x0F;

	public static final short EF_DG16 = (short) 0x0010;

	public static final byte SF_DG16 = (byte) 0x10;

	/**
	 * The security document.
	 */
	public static final short EF_SOD = 0x001D;

	public static final byte SF_SOD = 0x1D;

	/**
	 * File indicating which data groups are present and security mechanism
	 * indicators.
	 */
	public static final short EF_COM = 0x001E;

	public static final byte SF_COM = 0x1E;

	/**
	 * The file read block size, some cards cannot handle large values.
	 *
	 * TODO: get the read block size from the card FCI data or similar.
	 *
	 * @deprecated hack
	 */
	public static int maxBlockSize = 255;

	private static final int SESSION_STOPPED_STATE = 0;

	private static final int SESSION_STARTED_STATE = 1;

	private static final int BAC_AUTHENTICATED_STATE = 2;

	private static final int AA_AUTHENTICATED_STATE = 3;

	private static final int CA_AUTHENTICATED_STATE = 5;

	private static final int TA_AUTHENTICATED_STATE = 6;

	private static final int EAC_AUTHENTICATED_STATE = 7;

	private int state;

	private Collection<AuthListener> authListeners;

	private SecureMessagingWrapper wrapper;

	private Signature aaSignature;

	private MessageDigest aaDigest;

	private Cipher aaCipher;

	private Random random;

	private CardFileSystem fs;

	/**
	 * Creates a new card for some websites.
	 *
	 * @param service another service which will deal with sending the apdus to
	 * the card.
	 *
	 * @throws GeneralSecurityException when the available JCE providers cannot
	 * provide the necessary cryptographic primitives.
	 */
	public BasicService(CardService service) throws CardServiceException {
		super(service);
		try {
			aaSignature = Signature.getInstance("SHA1WithRSA/ISO9796-2");
			aaDigest = MessageDigest.getInstance("SHA1");
			aaCipher = Cipher.getInstance("RSA/NONE/NoPadding");
			random = new SecureRandom();
			authListeners = new ArrayList<AuthListener>();
			fs = new CardFileSystem();
		} catch (GeneralSecurityException gse) {
			throw new CardServiceException(gse.toString());
		}
		state = SESSION_STOPPED_STATE;
	}

	/**
	 * Opens a session. This is done by connecting to the card, selecting the
	 * application.
	 */
	public void open() throws CardServiceException {
		if (isOpen()) {
			return;
		}
		super.open();
		state = SESSION_STARTED_STATE;
	}

	public boolean isOpen() {
		return (state != SESSION_STOPPED_STATE);
	}

	/**
	 * Performs the <i>Basic Access Control</i> protocol.
	 *
	 * @param keySeedString user password
	 *
	 * @throws CardServiceException if authentication failed
	 */
	public synchronized void doBAC(byte[] keySeed) throws CardServiceException {
		try {
			if (keySeed == null) {
				return;
			}
			if (keySeed.length < 16) {
				throw new IllegalStateException("Key seed too short");
			}
			SecretKey kEnc = CryptoUtils.deriveKey(keySeed,
					CryptoUtils.ENC_MODE);
			SecretKey kMac = CryptoUtils.deriveKey(keySeed,
					CryptoUtils.MAC_MODE);
			byte[] rndICC = sendGetChallenge(wrapper);
			byte[] rndIFD = new byte[8];
			random.nextBytes(rndIFD);
			byte[] kIFD = new byte[16];
			random.nextBytes(kIFD);
			byte[] response = sendMutualAuth(rndIFD, rndICC, kIFD, kEnc, kMac);
			byte[] kICC = new byte[16];
			System.arraycopy(response, 16, kICC, 0, 16);
			keySeed = new byte[16];
			for (int i = 0; i < 16; i++) {
				keySeed[i] = (byte) ((kIFD[i] & 0xFF) ^ (kICC[i] & 0xFF));
			}
			SecretKey ksEnc = CryptoUtils.deriveKey(keySeed,
					CryptoUtils.ENC_MODE);
			SecretKey ksMac = CryptoUtils.deriveKey(keySeed,
					CryptoUtils.MAC_MODE);
			long ssc = CryptoUtils.computeSendSequenceCounter(rndICC, rndIFD);
			wrapper = new SecureMessagingWrapper(ksEnc, ksMac, ssc);
			BACEvent event = new BACEvent(this, rndICC, rndIFD, kICC, kIFD,
					true);
			notifyBACPerformed(event);
			state = BAC_AUTHENTICATED_STATE;
		} catch (GeneralSecurityException gse) {
			throw new CardServiceException(gse.toString());
		}
	}

	/**
	 * Adds an authentication event listener.
	 *
	 * @param l listener
	 */
	public void addAuthenticationListener(AuthListener l) {
		authListeners.add(l);
	}

	/**
	 * Removes an authentication event listener.
	 *
	 * @param l listener
	 */
	public void removeAuthenticationListener(AuthListener l) {
		authListeners.remove(l);
	}

	/**
	 * Notifies listeners about BAC events.
	 *
	 * @param event BAC event
	 */
	protected void notifyBACPerformed(BACEvent event) {
		for (AuthListener l : authListeners) {
			l.performedBAC(event);
		}
	}

	/**
	 * Performs the <i>Active Authentication</i> protocol.
	 *
	 * @param publicKey the public key to use (usually read from the card, DG15)
	 *
	 * @return a boolean indicating whether the card was authenticated
	 *
	 * @throws CardServiceException if something goes wrong
	 */
	public boolean doAA(PublicKey publicKey) throws CardServiceException {
		try {
			byte[] m2 = new byte[8];
			random.nextBytes(m2);
			byte[] response = sendAA(publicKey, m2);
			aaCipher.init(Cipher.DECRYPT_MODE, publicKey);
			aaSignature.initVerify(publicKey);
			int digestLength = aaDigest.getDigestLength();
			byte[] plaintext = aaCipher.doFinal(response);
			byte[] m1 = CryptoUtils.recoverMessage(digestLength, plaintext);
			aaSignature.update(m1);
			aaSignature.update(m2);
			boolean success = aaSignature.verify(response);
			AAEvent event = new AAEvent(this, publicKey, m1, m2, success);
			notifyAAPerformed(event);
			if (success) {
				state = AA_AUTHENTICATED_STATE;
			}
			return success;
		} catch (IllegalArgumentException iae) {
			throw new CardServiceException(iae.toString());
		} catch (GeneralSecurityException gse) {
			throw new CardServiceException(gse.toString());
		}
	}

	/**
	 * Performs the Chip Authentication (CA) part of the EAC protocol. In short,
	 * authenticate the chip with DH key aggrement protocol (new secure
	 * messaging keys are created then).
	 *
	 * @param keyId passport's public key id (stored in DG14), -1 if none.
	 * Currently unused.
	 * @param key cards public key (stored in DG14 on the card).
	 * @return the EAP key pair used by the host
	 * @throws CardServiceException on error
	 */
	public synchronized KeyPair doCA(int keyId, PublicKey key)
			throws CardServiceException {
		try {
			String algName = (key instanceof ECPublicKey) ? "ECDH" : "DH";
			KeyPairGenerator genKey = KeyPairGenerator.getInstance(algName);
			AlgorithmParameterSpec spec = null;
			if ("DH".equals(algName)) {
				DHPublicKey k = (DHPublicKey) key;
				spec = k.getParams();
			} else {
				ECPublicKey k = (ECPublicKey) key;
				spec = k.getParams();
			}

			genKey.initialize(spec);
			KeyPair keyPair = genKey.generateKeyPair();

			KeyAgreement agreement = KeyAgreement.getInstance("ECDH", "BC");
			agreement.init(keyPair.getPrivate());
			agreement.doPhase(key, true);

			// NOTE: this step is done, because of the Java Card API
			// limitations,
			// this is not in the specs! Normally the result should not be
			// hashed.
			MessageDigest md = MessageDigest.getInstance("SHA1");
			byte[] secret = md.digest(agreement.generateSecret());

			byte[] keyData = null;
			if ("DH".equals(algName)) {
				DHPublicKey k = (DHPublicKey) keyPair.getPublic();
				keyData = k.getY().toByteArray();
			} else {
				org.bouncycastle.jce.interfaces.ECPublicKey k = (org.bouncycastle.jce.interfaces.ECPublicKey) keyPair
						.getPublic();
				keyData = k.getQ().getEncoded();
			}
			keyData = tagData((byte) 0x91, keyData);

			sendMSE(wrapper, 0x41, 0xA6, keyData);
			SecretKey ksEnc = CryptoUtils.deriveKey(secret,
					CryptoUtils.ENC_MODE);
			SecretKey ksMac = CryptoUtils.deriveKey(secret,
					CryptoUtils.MAC_MODE);
			wrapper = new SecureMessagingWrapper(ksEnc, ksMac, 0L);
			state = CA_AUTHENTICATED_STATE;
			return keyPair;
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new CardServiceException(
					"Problem occured during Chip Authentication: "
					+ ex.getMessage());
		}
	}

	/**
	 * Performs the Terminal Authentication (TA) part of the EAC protocol In
	 * short: (a) feed the sequence of terminal certificates to the card for
	 * verification. (b) get a challenge from the card, sign it with terminal
	 * private key, send back to the card for verification.
	 *
	 * @param terminalCertificates the list/chain of terminal certificates
	 * @param terminalKey terminal private key
	 * @param sicId the SIC ID number
	 * @return the card's challenge
	 * @throws CardServiceException on error
	 */
	public synchronized byte[] doTA(List<CVCertificate> terminalCertificates,
			PrivateKey terminalKey, String sicId) throws CardServiceException {
		try {
			String sigAlg = null;

			// Send the certificates for verification
			for (CVCertificate cert : terminalCertificates) {
				byte[] body = cert.getCertificateBody().getDEREncoded();
				byte[] sig = cert.getSignatureWrapped();
				byte[] certData = new byte[body.length + sig.length];
				System.arraycopy(body, 0, certData, 0, body.length);
				System.arraycopy(sig, 0, certData, body.length, sig.length);
				sendPSO(wrapper, certData);
				sigAlg = AlgorithmUtil.getAlgorithmName(cert
						.getCertificateBody().getPublicKey()
						.getObjectIdentifier());
			}
			// Send get challenge + mutual authentication

			byte[] challenge = sendGetChallenge(wrapper);

			Signature sig = Signature.getInstance(sigAlg);
			sig.initSign(terminalKey);

			ByteArrayOutputStream dtbs = new ByteArrayOutputStream();
			dtbs.write(sicId.getBytes());
			dtbs.write(challenge);

			sig.update(dtbs.toByteArray());
			// NOTE reread the specs to find out what the exact format of the
			// signature should be! (Passport, e.g., requires stripping of the
			// ASN.1 headers)
			sendMutualAuthenticate(wrapper, sig.sign());
			state = TA_AUTHENTICATED_STATE;
			return challenge;
		} catch (CardServiceException cse) {
			throw cse;
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new CardServiceException("Problem occured during TA: "
					+ ex.getMessage());
		}

	}

	/**
	 * Performs the EAC protocol. i.e. Do CA and then TA.
	 *
	 * @param keyId passport's public key id (stored in DG14), -1 if none.
	 * Currently unused.
	 * @param key cards EC public key (stored in DG14 on the card).
	 * @param terminalCertificates the list/chain of terminal certificates
	 * @param terminalKey terminal private key
	 * @param sicId the SIC ID number
	 * @throws CardServiceException on error
	 */
	public synchronized void doEAC(int keyId, PublicKey key,
			List<CVCertificate> terminalCertificates, PrivateKey terminalKey,
			String sicId) throws CardServiceException {

		KeyPair keyPair = doCA(keyId, key);
		byte[] challenge = doTA(terminalCertificates, terminalKey, sicId);
		EACEvent event = new EACEvent(this, keyId, keyPair,
				terminalCertificates, terminalKey, sicId, challenge, true);
		notifyEACPerformed(event);
		state = EAC_AUTHENTICATED_STATE;
	}

	/**
	 * Simple method to attach single byte tag to the data.
	 *
	 * @param tag the tag
	 * @param data the data
	 * @return the tagged data
	 */
	static byte[] tagData(byte tag, byte[] data) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			out.write(tag);
			out.write(data.length);
			out.write(data);
		} catch (IOException ioe) {
		}
		return out.toByteArray();
	}

	/**
	 * Performs the <i>Active Authentication</i> protocol. This method just
	 * gives the response from the card without checking. Use
	 * {@link #doAA(PublicKey)} instead.
	 *
	 * @param publicKey the public key to use (usually read from the card)
	 * @param challenge the random challenge of exactly 8 bytes
	 *
	 * @return response from the card
	 */
	public byte[] sendAA(PublicKey publicKey, byte[] challenge)
			throws CardServiceException {
		if (publicKey == null) {
			throw new IllegalArgumentException("AA failed: bad key");
		}
		if (challenge == null || challenge.length != 8) {
			throw new IllegalArgumentException("AA failed: bad challenge");
		}
		byte[] response = sendInternalAuthenticate(wrapper, challenge);
		return response;
	}

	/**
	 * Notifies listeners about AA event.
	 *
	 * @param event AA event.
	 */
	protected void notifyAAPerformed(AAEvent event) {
		for (AuthListener l : authListeners) {
			l.performedAA(event);
		}
	}

	/**
	 * Notifies listeners about EAC event.
	 *
	 * @param event EAC event.
	 */
	protected void notifyEACPerformed(EACEvent event) {
		for (AuthListener l : authListeners) {
			l.performedEAC(event);
		}
	}

	public void close() {
		try {
			wrapper = null;
			super.close();
		} finally {
			state = SESSION_STOPPED_STATE;
		}
	}

	/**
	 * Gets the wrapper. Returns <code>null</code> until BAC has been performed.
	 *
	 * @return the wrapper
	 */
	public SecureMessagingWrapper getWrapper() {
		return wrapper;
	}

	public FileSystemStructured getFileSystem() {
		return fs;
	}

	/**
	 * Gets the file indicated by a file identifier.
	 *
	 * @param fid file identifier
	 *
	 * @return the file
	 *
	 * @throws IOException if the file cannot be read
	 */
	public CardFileInputStream readFile() throws CardServiceException {
		return new CardFileInputStream(maxBlockSize, fs);
	}

	public CardFileInputStream readDataGroup(int tag)
			throws CardServiceException {
		short fid = FileStructure.lookupFIDByTag(tag);
		fs.selectFile(fid);
		return readFile();
	}

	private class CardFileSystem implements FileSystemStructured {

		private CardFileInfo selectedFile;

		public synchronized byte[] readBinary(int offset, int length)
				throws CardServiceException {
			return sendReadBinary(wrapper, (short) offset, length);
		}

		public synchronized void selectFile(short fid)
				throws CardServiceException {
			sendSelectFile(wrapper, fid);
			selectedFile = new CardFileInfo(fid, getFileLength());
		}

		public synchronized int getFileLength() throws CardServiceException {
			try {
				byte[] prefix = readBinary(0, 8);
				ByteArrayInputStream baIn = new ByteArrayInputStream(prefix);
				BERTLVInputStream tlvIn = new BERTLVInputStream(baIn);
				tlvIn.readTag();
				int vLength = tlvIn.readLength();
				int tlLength = prefix.length - baIn.available();
				return tlLength + vLength;
			} catch (IOException ioe) {
				throw new CardServiceException(ioe.toString());
			}
		}

		public FileInfo[] getSelectedPath() {
			return new CardFileInfo[]{selectedFile};
		}

	}

	private class CardFileInfo extends FileInfo {

		private short fid;

		private int length;

		public CardFileInfo(short fid, int length) {
			this.fid = fid;
			this.length = length;
		}

		public short getFID() {
			return fid;
		}

		public int getFileLength() {
			return length;
		}
	}
}
