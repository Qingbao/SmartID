package smartid.hig.no.lds;

import java.security.cert.X509Certificate;

public interface DocumentSigner {

	/**
	 * An interface that different document signers should implement. For a
	 * simple signer that would just be a call to a signature object with a
	 * provided key. For a proper secure signer this would be some sort of a
	 * delegation service (to a smart card, web service, etc.).
	 */
	/**
	 * Informs the signer of the certificate for which a private key should be
	 * used.
	 *
	 * @param ceritificate
	 */
	public void setCertificate(X509Certificate certificate);

	/**
	 * Requests a signing of the data.
	 *
	 * @param dataToBeSigned Data to be signed
	 * @return the signed data, null on error
	 */
	public byte[] signData(byte[] dataToBeSigned);

}
