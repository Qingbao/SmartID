/**
 *
 */
package smartid.hig.no.lds;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;

import net.sourceforge.scuba.tlv.BERTLVInputStream;
import net.sourceforge.scuba.tlv.BERTLVObject;

/**
 * File structure for the EF_DG15 file. Datagroup 15 contains the algorithm
 * identifier and public key used in Active Authentication.
 *
 *
 *
 *
 */
public class DG_15_FILE extends DataGroups {

	private PublicKey publicKey;

	/**
	 * Constructs a new file. The signature algorithm is by default set to
	 * SHA256withRSA.
	 *
	 * @param publicKey the key to store in this file
	 */
	public DG_15_FILE(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	/**
	 * Constructs a new file based on the data in <code>in</code>.
	 *
	 * @param in the input stream with the file contents
	 *
	 * @throws IllegalArgumentException if the data could not be decoded
	 */
	public DG_15_FILE(InputStream in) {
		try {
			BERTLVInputStream tlvIn = new BERTLVInputStream(in);
			if (tlvIn.readTag() != EF_DG15_TAG) {
				throw new IOException("Wrong tag.");
			}
			tlvIn.readLength();
			ASN1InputStream asn1in = new ASN1InputStream(in);
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(asn1in.readObject().getEncoded());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			publicKey = keyFactory.generatePublic(pubKeySpec);
		} catch (Exception e) {
			throw new IllegalArgumentException(e.toString());
		}
	}

	/**
	 * Gets the BERTLV encoded form of this file
	 */
	public byte[] getEncoded() {
		if (isSourceConsistent) {
			return sourceObject.getEncoded();
		}
		try {
			BERTLVObject ef
					= new BERTLVObject(FileStructure.EF_DG15_TAG,
							publicKey.getEncoded(), false);
			sourceObject = ef;
			isSourceConsistent = true;
			return ef.getEncoded();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public int getTag() {
		return EF_DG15_TAG;
	}

	/**
	 * Gets the public key stored in this file.
	 *
	 * @return the public key
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}

	public String toString() {
		return "DG15File: " + publicKey.toString();
	}

	// For testing only:
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		PublicKey pub = keyGen.generateKeyPair().getPublic();
    	//System.out.println(pub.toString());

		DG_15_FILE d1 = new DG_15_FILE(pub);
		System.out.println(d1.toString());

		byte[] enc = d1.getEncoded();

		DG_15_FILE d2 = new DG_15_FILE(new ByteArrayInputStream(enc));

		System.out.println(d2.toString());

	}

}
