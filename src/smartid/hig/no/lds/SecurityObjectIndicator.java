
package smartid.hig.no.lds;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

/**
 * Encapsulates Security Mechanism/Object Indicator. Stores the SOI as a
 * DERSequence.
 * 
 */
public class SecurityObjectIndicator {

    protected DERSequence sequence;

    /**
     * The default constructor.
     * 
     */
    public SecurityObjectIndicator() {
    }

    /**
     * Creates a new SOI based on the given DER sequence.
     * 
     * @param sequence
     *            the DER sequence with the SOI.
     */
    public SecurityObjectIndicator(DERSequence sequence) {
        this.sequence = sequence;
    }

    /**
     * Gets the DER sequence representing this SOI.
     * 
     * @return the DER sequence representing this SOI.
     */
    public DERSequence getDERSequence() {
        return sequence;
    }

    /**
     * Gets the data group number this SOI is attached to.
     * 
     * @return the data group number this SOI is attached to.
     */
    public int getDGNumber() {
        try {
            DERInteger dg = (DERInteger) ((DERSequence) ((DERSequence) sequence
                    .getObjectAt(0)).getObjectAt(1)).getObjectAt(1);
            return dg.getValue().intValue();
        } catch (Exception e) {
            return -1;
        }

    }

    /**
     * Gets the SOI's ASN1 identifier.
     * 
     * @return the SOI's ASN1 identifier.
     */
    public DERObjectIdentifier getIdentifier() {
        try {
            DERObjectIdentifier id = (DERObjectIdentifier) ((DERSequence) sequence
                    .getObjectAt(0)).getObjectAt(0);
            return id;
        } catch (Exception e) {
            return null;
        }

    }

    public String toString() {
        return "SOI DG" + getDGNumber() + ", id: " + getIdentifier().getId();
    }

}
