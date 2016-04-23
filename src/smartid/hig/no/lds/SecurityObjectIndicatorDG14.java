package smartid.hig.no.lds;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.ejbca.cvc.CVCertificate;

/**
 * Encapsulates Security Mechanism/Object Indicator for DG14.
 *
 *
 */
public class SecurityObjectIndicatorDG14 extends SecurityObjectIndicator {

	public static final DERObjectIdentifier id_bac_conf1 = new DERObjectIdentifier(
			"1.0.6666.3.2.1.1");

	public static final DERObjectIdentifier id_eac = new DERObjectIdentifier(
			"1.0.6666.3.2.2");

	private List<Integer> dataGroups = new ArrayList<Integer>();

	private byte[] certificateSubjectId;

	/**
	 * Creates a new SOI DG14 object.
	 *
	 * @param cvCertificate the EAC CV certificate for this SOI
	 *
	 * @param dataGroups data groups that this SOI applies to
	 */
	public SecurityObjectIndicatorDG14(CVCertificate cvCertificate,
			List<Integer> dataGroups) {
		try {
			this.dataGroups.addAll(dataGroups);
			certificateSubjectId = new byte[17];
			byte[] t = cvCertificate.getCertificateBody().getHolderReference()
					.getConcatenated().getBytes();
			System.arraycopy(t, 0, certificateSubjectId, 1, t.length);
			certificateSubjectId[0] = (byte) t.length;

			DERSequence paramEAP = new DERSequence(new ASN1Encodable[]{
				new DERInteger(0), new DERInteger(14), id_bac_conf1,
				new DEROctetString(certificateSubjectId),
				new DEROctetString(new byte[17])});
			DERSequence eapId = new DERSequence(new ASN1Encodable[]{id_eac,
				paramEAP});
			DERInteger[] dgs = new DERInteger[dataGroups.size()];
			for (int i = 0; i < dgs.length; i++) {
				dgs[i] = new DERInteger(dataGroups.get(i));
			}
			sequence = new DERSequence(new ASN1Encodable[]{eapId,
				new DERSet(dgs)});

		} catch (Exception e) {
			throw new IllegalArgumentException();
		}
	}

	/**
	 * Creates a new SOI DG14 object based on the data in <code>seq</code>.
	 */
	public SecurityObjectIndicatorDG14(DERSequence seq) {
		this.sequence = seq;
		DERObjectIdentifier id = (DERObjectIdentifier) ((DERSequence) sequence
				.getObjectAt(0)).getObjectAt(0);
		DERInteger ver = (DERInteger) ((DERSequence) ((DERSequence) sequence
				.getObjectAt(0)).getObjectAt(1)).getObjectAt(0);
		DERInteger dg = (DERInteger) ((DERSequence) ((DERSequence) sequence
				.getObjectAt(0)).getObjectAt(1)).getObjectAt(1);
		DERObjectIdentifier bap = (DERObjectIdentifier) ((DERSequence) ((DERSequence) sequence
				.getObjectAt(0)).getObjectAt(1)).getObjectAt(2);
		DEROctetString sub = (DEROctetString) ((DERSequence) ((DERSequence) sequence
				.getObjectAt(0)).getObjectAt(1)).getObjectAt(3);
		DERSet dgs = (DERSet) sequence.getObjectAt(1);
		if (!id.equals(id_eac) || ver.getValue().intValue() != 0
				|| dg.getValue().intValue() != 14 || !bap.equals(id_bac_conf1)) {
			throw new IllegalArgumentException();
		}
		certificateSubjectId = sub.getOctets();
		for (int i = 0; i < dgs.size(); i++) {
			dataGroups.add(new Integer(((DERInteger) dgs.getObjectAt(i))
					.getValue().intValue()));
		}
	}

	/**
	 * Gets the EAC certificate subject id.
	 *
	 * @return the EAC certificate subject id.
	 */
	public byte[] getCertificateSubjectId() {
		return certificateSubjectId;
	}

	public DERSequence getDERSequence() {
		return sequence;
	}

	/**
	 * Gets the data group numbers this SOI applies to.
	 *
	 * @return the data group numbers this SOI applies to.
	 */
	public List<Integer> getDataGroups() {
		return dataGroups;
	}

	public String toString() {
		String subject = "subject: "
				+ new String(certificateSubjectId, 1, certificateSubjectId[0]);
		String result = "SOI DG14, " + id_eac.getId() + ", " + subject;
		if (dataGroups.size() > 0) {
			result += ", DGs:";
			for (Integer i : dataGroups) {
				result += " DG" + i.toString();
			}
		}
		return result;
	}

}
