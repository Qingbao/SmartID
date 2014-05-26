/**
 * 
 */
package smartid.hig.no.lds;

import java.io.IOException;
import java.io.InputStream;

import net.sourceforge.scuba.tlv.BERTLVInputStream;
import net.sourceforge.scuba.tlv.BERTLVObject;

/**
 * Encapsulates a generic data group
 * 
 * 
 *
 */
public abstract class DataGroups extends FileStructure{

    protected int dataGroupTag;

    protected int dataGroupLength;

    /**
     * Constructor only visible to the other classes in this package.
     */
    DataGroups() {
    }

    protected DataGroups(InputStream in) {
        try {
            BERTLVInputStream tlvIn = new BERTLVInputStream(in);
            dataGroupTag = tlvIn.readTag();
            dataGroupLength = tlvIn.readLength();
        } catch (IOException ioe) {
            throw new IllegalArgumentException("Could not decode: "
                    + ioe.toString());
        }
    }

    /**
     * Constructor only visible to the other classes in this package.
     * 
     * @param object
     *            datagroup contents.
     */
    DataGroups(BERTLVObject object) {
        sourceObject = object;
        isSourceConsistent = true;
    }

    /**
     * Gets the BERTLV encoded form of this data group
     * 
     * @return the BERTLV encoded form of this data group
     */
    public byte[] getEncoded() {
        if (isSourceConsistent) {
            return sourceObject.getEncoded();
        }
        return null;
    }

    public String toString() {
        if (isSourceConsistent) {
            return sourceObject.toString();
        }
        return super.toString();
    }

    /**
     * The data group tag.
     * 
     * @return the tag of the data group
     */
    public int getTag() {
        return dataGroupTag;
    }

    /**
     * The length of the value of the data group.
     * 
     * @return the length of the value of the data group
     */
    public int getLength() {
        return dataGroupLength;
    }
}
