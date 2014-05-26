
package smartid.hig.no.lds;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;

/**
 * Encapsulates Security Mechanism/Object Indicator for DG15.
 * 
 */
public class SecurityObjectIndicatorDG15 extends SecurityObjectIndicator {

    public static final DERObjectIdentifier id_aa = new DERObjectIdentifier(
            "1.0.6666.3.2.3");

    private List<Integer> dataGroups = new ArrayList<Integer>();

    /**
     * Creates a new SOI DG15 object.
     * 
     * @param dataGroups
     *            data groups that this SOI applies to
     */
    public SecurityObjectIndicatorDG15(List<Integer> dataGroups) {
        this.dataGroups.addAll(dataGroups);
        DERSequence paramAA = new DERSequence(new ASN1Encodable[] {
                new DERInteger(0), new DERInteger(15) });
        DERSequence aaId = new DERSequence(
                new ASN1Encodable[] { id_aa, paramAA });
        DERInteger[] dgs = new DERInteger[this.dataGroups.size()];
        for (int i = 0; i < dgs.length; i++) {
            dgs[i] = new DERInteger(this.dataGroups.get(i));
        }
        sequence = new DERSequence(
                new ASN1Encodable[] { aaId, new DERSet(dgs) });

    }

    /**
     * Creates a new SOI DG15 object based on the data in <code>seq</code>.
     */
    public SecurityObjectIndicatorDG15(DERSequence seq) {
        this.sequence = seq;
        DERObjectIdentifier id = (DERObjectIdentifier) ((DERSequence) sequence
                .getObjectAt(0)).getObjectAt(0);
        DERInteger ver = (DERInteger) ((DERSequence) ((DERSequence) sequence
                .getObjectAt(0)).getObjectAt(1)).getObjectAt(0);
        DERInteger dg = (DERInteger) ((DERSequence) ((DERSequence) sequence
                .getObjectAt(0)).getObjectAt(1)).getObjectAt(1);
        DERSet dgs = (DERSet) sequence.getObjectAt(1);
        if (!id.equals(id_aa) || ver.getValue().intValue() != 0
                || dg.getValue().intValue() != 15) {
            throw new IllegalArgumentException();
        }
        for (int i = 0; i < dgs.size(); i++) {
            dataGroups.add(new Integer(((DERInteger) dgs.getObjectAt(i))
                    .getValue().intValue()));
        }
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
        String result = "SOI DG15, " + id_aa.getId();
        if (dataGroups.size() > 0) {
            result += ", DGs:";
            for (Integer i : dataGroups) {
                result += " DG" + i.toString();
            }
        }
        return result;
    }

}
