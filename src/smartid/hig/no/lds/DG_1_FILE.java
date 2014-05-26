/**
 * 
 */
package smartid.hig.no.lds;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import net.sourceforge.scuba.tlv.BERTLVInputStream;
import net.sourceforge.scuba.tlv.BERTLVObject;
import net.sourceforge.scuba.util.Hex;
import smartid.hig.no.services.BasicInfo;

/**
 * File structure for the EF_DG1 file that contains basic information.
 * 
 * 
 *
 */
public class DG_1_FILE extends DataGroups{
	
	private static final short DG1_INFO_TAG = 0x5F1F;

    private BasicInfo info;


    /**
     * Constructs a new file.
     * 
     * @param info
     *            the info object
     */
    public DG_1_FILE(BasicInfo info) {
        this.info = info;
    }

    /**
     * Constructs a new file based on the data in <code>in</code>.
     * 
     * @param in
     *            the input stream with the data to be decoded
     * @throws IOException
     *             if decoding fails
     */
    public DG_1_FILE(InputStream in) throws IOException {
        BERTLVInputStream tlvIn = new BERTLVInputStream(in);
        int tag = tlvIn.readTag();
        if (tag != FileStructure.EF_DG1_TAG) {
            throw new IllegalArgumentException("Expected EF_DG1_TAG");
        }
        isSourceConsistent = false;

        tlvIn.readLength();
        byte[] valueBytes = tlvIn.readValue();
        BERTLVObject mainObject = new BERTLVObject(tag, valueBytes);
        BERTLVObject demographicObject = mainObject
                .getSubObject(DG1_INFO_TAG);
        
        this.info = new BasicInfo(new ByteArrayInputStream(
                (byte[]) demographicObject.getValue()));
            
    }

    public int getTag() {
        return EF_DG1_TAG;
    }

    /**
     * Gets the dg1 information stored in this file.
     * 
     * @return the dg1 information
     */
    public BasicInfo getInfo() {
        return info;
    }

    public String toString() {
        return "DG1File: " + info.toString() + "\n";
    }

   
    /**
     * Gets the BERTLV encoded form of this file.
     */
    public byte[] getEncoded() {
        if (isSourceConsistent) {
            return sourceObject.getEncoded();
        }
        try {
            BERTLVObject result = new BERTLVObject(EF_DG1_TAG,
                    new BERTLVObject(DG1_INFO_TAG, info.getEncoded()));
            
            sourceObject = result;
            result.reconstructLength();
            isSourceConsistent = true;
            return result.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    //test
    public static void main(String[] args) throws IOException {
    	
    	DG_1_FILE d1 = new DG_1_FILE(new BasicInfo("a","b","c","d","e", "f","g","h","i","j"));
    	System.out.println(d1.toString());
    	 byte[] enc = d1.getEncoded();
    	 System.out.println(Hex.bytesToHexString(enc));
    	 
    	 DG_1_FILE d2 = new DG_1_FILE(new ByteArrayInputStream(enc));
    	 System.out.println(d2.toString());
    	 
    	
    }

}
