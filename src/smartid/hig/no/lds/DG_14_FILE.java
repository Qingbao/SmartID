/**
 *
 */
package smartid.hig.no.lds;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import javax.crypto.interfaces.DHPublicKey;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;

import net.sourceforge.scuba.tlv.BERTLVInputStream;
import net.sourceforge.scuba.tlv.BERTLVObject;

/**
 * File structure for the EF_DG14 file. Part of EAC, i.e. Chip Authentication.
 * Contains EAC key agreement public key.
 *
 *
 *
 */
public class DG_14_FILE extends DataGroups {

	private static final DERObjectIdentifier ID_ACAUTH = new DERObjectIdentifier(
			"1.0.18013.3.3.1");

    // Either we have one key with no id, or some keys (one also possible) each
	// marked with an integer.
	private Map<Integer, PublicKey> publicKeys;

	/**
	 * Constructs a new file from the contents in <code>in</code>.
	 *
	 * @param in the input stream with the file contents
	 *
	 * @throws IOException if the data cannot be decoded
	 */
	public DG_14_FILE(InputStream in) throws IOException {
		BERTLVInputStream tlvIn = new BERTLVInputStream(in);
		int tag = tlvIn.readTag();
		if (tag != FileStructure.EF_DG14_TAG) {
			throw new IllegalArgumentException("Expected EF_DG14_TAG");
		}
		isSourceConsistent = false;
		tlvIn.readLength();
		byte[] valueBytes = tlvIn.readValue();
		DERSet set = (DERSet) (new ASN1InputStream(valueBytes).readObject());
		Enumeration e = set.getObjects();
		publicKeys = new TreeMap<Integer, PublicKey>();
		int i = 0;
		while (e.hasMoreElements()) {
			DERSequence secInfo = (DERSequence) e.nextElement();
			DERObjectIdentifier id = (DERObjectIdentifier) secInfo
					.getObjectAt(0);
			if (!id.equals(ID_ACAUTH)) {
				throw new IllegalStateException("Wrong OID " + id.getId());
			}
			DERSequence key = (DERSequence) secInfo.getObjectAt(1);
			if (key.size() == 2) {
				DERInteger keyNum = (DERInteger) key.getObjectAt(0);
				DERObject keyData = key.getObjectAt(1).getDERObject();
				publicKeys.put(new Integer(keyNum.getValue().intValue()),
						getKey(keyData));
			} else {
				DERObject keyData = key.getObjectAt(0).getDERObject();
				publicKeys.put(new Integer(-1), getKey(keyData));
			}
			i++;
		}
	}

	private PublicKey getKey(DERObject o) throws IOException {

		try {
			KeySpec spec = new X509EncodedKeySpec(o.getDEREncoded());
			KeyFactory kf = KeyFactory.getInstance("DH");
			return (ECPublicKey) kf.generatePublic(spec);
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new IllegalArgumentException("Could not decode key.");
		}
	}

	/**
	 * Constructs a new file with the given EC public key.
	 *
	 * @param publicKey the EC public key
	 */
	public DG_14_FILE(PublicKey publicKey) {
		this.publicKeys = new TreeMap<Integer, PublicKey>();
		this.publicKeys.put(new Integer(-1), publicKey);
	}

	/**
	 * Constructs a new file with the list of given EC public keys
	 *
	 * @param keys a map containg a list of EC public keys indexed by integers
	 */
	public DG_14_FILE(Map<Integer, PublicKey> keys) {
		this.publicKeys = new TreeMap<Integer, PublicKey>();
		publicKeys.putAll(keys);
	}

	public int getTag() {
		return EF_DG14_TAG;
	}

	/**
	 * Return the number of keys stored in this file.
	 *
	 * @return the number of keys stored in this file
	 */
	public int getSize() {
		return publicKeys.size();
	}

	/**
	 * Gets the key indicated by the integer id
	 *
	 * @param id the id of the key
	 * @return the associated key
	 */
	public PublicKey getKey(Integer id) {
		if (getSize() == 0) {
			return null;
		}
		return publicKeys.get(id);
	}

	/**
	 * Gets the set of key ids (possibly empty)
	 *
	 * @return the set of key ids
	 */
	public Set<Integer> getIds() {
		return publicKeys.keySet();
	}

	public String toString() {
		return "DG14File: " + publicKeys.toString();
	}

	/**
	 * Returns a SubjectPublicKeyInfo object for a given EC public key. Noramlly
	 * this is done with a combination of <code>key.getEncoded()</code> and a
	 * new ASN1 stream.
	 *
	 * @param key the EC public key
	 * @return SubjectPublicKeyInfo with the key, null on problems
	 */
	private SubjectPublicKeyInfo getSubjectPublicKeyInfo(PublicKey key) {

		try {
			if (key instanceof ECPublicKey) {

				SubjectPublicKeyInfo vInfo = new SubjectPublicKeyInfo(
						(DERSequence) new ASN1InputStream(key.getEncoded())
						.readObject());
				DERObject parameters = vInfo.getAlgorithmId().getParameters()
						.getDERObject();
				X9ECParameters params = null;
				if (parameters instanceof DERObjectIdentifier) {
					params = X962NamedCurves
							.getByOID((DERObjectIdentifier) parameters);
					org.bouncycastle.math.ec.ECPoint p = params.getG();
					p = p.getCurve().createPoint(p.getX().toBigInteger(),
							p.getY().toBigInteger(), false);
					params = new X9ECParameters(params.getCurve(), p, params
							.getN(), params.getH(), params.getSeed());
				} else {
					return vInfo;

				}

				org.bouncycastle.jce.interfaces.ECPublicKey pub = (org.bouncycastle.jce.interfaces.ECPublicKey) key;
				AlgorithmIdentifier id = new AlgorithmIdentifier(vInfo
						.getAlgorithmId().getObjectId(), params.getDERObject());
				org.bouncycastle.math.ec.ECPoint p = pub.getQ();
                // In case we would like to compress the point:
				// p = p.getCurve().createPoint(p.getX().toBigInteger(),
				// p.getY().toBigInteger(), true);
				vInfo = new SubjectPublicKeyInfo(id, p.getEncoded());
				return vInfo;
			} else if (key instanceof DHPublicKey) {
				return new SubjectPublicKeyInfo(
						(DERSequence) new ASN1InputStream(key.getEncoded())
						.readObject());
			} else {
				throw new IllegalArgumentException(
						"Unrecognized key type, should be DH or EC");
			}

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Gets the BERTLV encoded form of this file.
	 */
	public byte[] getEncoded() {
		if (isSourceConsistent) {
			return sourceObject.getEncoded();
		}
		try {
			DERSet securityInfos = null;
			ASN1Encodable[] infos = new ASN1Encodable[publicKeys.size()];
			int i = 0;
			Iterator<Integer> it = publicKeys.keySet().iterator();
			while (it.hasNext()) {
				Integer num = it.next();
				DERObject key = getSubjectPublicKeyInfo(publicKeys.get(num))
						.getDERObject();
				DERSequence oneKey = null;
				if (num == -1) {
					oneKey = new DERSequence(new ASN1Encodable[]{key});
				} else {
					oneKey = new DERSequence(new ASN1Encodable[]{
						new DERInteger(num.intValue()), key});
				}
				infos[i++] = new DERSequence(new ASN1Encodable[]{ID_ACAUTH,
					oneKey});
			}
			securityInfos = new DERSet(infos);

			BERTLVObject result = new BERTLVObject(EF_DG14_TAG, securityInfos
					.getEncoded());
			sourceObject = result;
			isSourceConsistent = true;
			return result.getEncoded();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	// For testing only:
	public static void main(String[] args) {
		try {
			Security
					.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			KeyPairGenerator keyGen = KeyPairGenerator
					.getInstance("ECDH", "BC");
			keyGen.initialize(new ECGenParameterSpec("c2pnb163v1"));
			KeyPair keyPair1 = keyGen.generateKeyPair();
			KeyPair keyPair2 = keyGen.generateKeyPair();

            // ECPoint p = ((ECPrivateKey) keyPair1.getPrivate()).getParams()
			// .getGenerator();
			DG_14_FILE file1 = new DG_14_FILE((ECPublicKey) keyPair1.getPublic());
			HashMap<Integer, ECPublicKey> map = new HashMap<Integer, ECPublicKey>();
			map.put(new Integer(10), (ECPublicKey) keyPair1.getPublic());
			map.put(new Integer(20), (ECPublicKey) keyPair2.getPublic());
			// DG14File file2 = new DG14File(map);

			System.out.println("File 1 : " + file1);
			// System.out.println("File 2 : " + file2);

			DG_14_FILE file1parsed = new DG_14_FILE(new ByteArrayInputStream(file1
					.getEncoded()));
            // DG14File file2parsed = new DG14File(new
			// ByteArrayInputStream(file2.getEncoded()));

			System.out.println("File 1p: " + file1parsed);
			// System.out.println("File 2p: " + file2parsed);

			boolean res1 = Arrays.equals(file1.getEncoded(), file1parsed
					.getEncoded());
            // boolean res2 = Arrays.equals(file2.getEncoded(),
			// file2parsed.getEncoded());

			System.out.println("res1: " + res1);
			// System.out.println("res2: " + res2);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
