package smartid.hig.no.events;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.EventObject;
import java.util.List;

import org.ejbca.cvc.CVCertificate;

import smartid.hig.no.services.BasicService;
import smartid.hig.no.services.SecureMessagingWrapper;

/**
 * Event to indicate EAC protocol was executed.
 *
 *
 */
public class EACEvent extends EventObject {

	private static final long serialVersionUID = 9152021138227662926L;

	private BasicService service;

	private KeyPair keyPair;

	private List<CVCertificate> terminalCertificates = new ArrayList<CVCertificate>();

	private PrivateKey terminalKey;

	private boolean success;

	private String sicId;

	private int keyId;

	private byte[] cardChallenge;

	/**
	 * Constructs a new event.
	 *
	 * @param service event source
	 * @param keyPair the ECDH key pair used for authenticating the chip
	 * @param success status of protocol
	 */
	public EACEvent(BasicService service, int keyId, KeyPair keyPair,
			List<CVCertificate> terminalCertificates, PrivateKey terminalKey,
			String sicId, byte[] cardChallenge, boolean success) {
		super(service);
		this.service = service;
		this.keyId = keyId;
		this.keyPair = keyPair;
		this.success = success;
		for (CVCertificate c : terminalCertificates) {
			this.terminalCertificates.add(c);
		}
		this.terminalKey = terminalKey;
		this.sicId = sicId;
		this.cardChallenge = cardChallenge;
	}

	/**
	 * Gets the resulting wrapper.
	 *
	 * @return the resulting wrapper
	 */
	public SecureMessagingWrapper getWrapper() {
		return service.getWrapper();
	}

	/**
	 * Gets the status of the executed EAC protocol run.
	 *
	 * @return status of the EAC protocol run.
	 */
	public boolean isSuccess() {
		return success;
	}

	/**
	 * Returns the ECDH host key pair used for EAC chip authentication.
	 *
	 * @return the ECDH host key pair used for EAC chip authentication
	 */
	public KeyPair getKeyPair() {
		return keyPair;
	}

	/**
	 * Returns the chain of CVCertificates used to authenticate the terminal to
	 * the card.
	 *
	 * @return the chain of CVCertificates used to authenticate the terminal to
	 * the card
	 */
	public List<CVCertificate> getCVCertificates() {
		return terminalCertificates;
	}

	/**
	 * Returns the terminal private key used during EAC.
	 *
	 * @return the terminal private key
	 */
	public PrivateKey getTerminalKey() {
		return terminalKey;
	}

	/**
	 * Returns the id of the card used during EAC.
	 *
	 * @return the id of the card
	 */
	public String getSicId() {
		return sicId;
	}

	/**
	 * Returns the id of the card's key used during EAC.
	 *
	 * @return the id of the card's key
	 */
	public int getKeyId() {
		return keyId;
	}

	/**
	 * Return the card's challenge generated during EAC.
	 *
	 * @return the card's challenge
	 */
	public byte[] getCardChallenge() {
		return cardChallenge;
	}

	public BasicService getService() {
		return service;
	}
}
