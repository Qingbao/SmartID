/**
 * 
 */
package smartid.hig.no.lds;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import net.sourceforge.scuba.tlv.BERTLVInputStream;
import net.sourceforge.scuba.tlv.BERTLVObject;
import net.sourceforge.scuba.util.Hex;

/**
 * File structure for the EF_DG3 file.
 * 
 * 
 *
 */
public class DG_3_FILE extends DataGroups {
	
	private static final short TAGS_TAG = 0x5C;
	
	 private static final short EMTRY_TAG = 0x5F01;

    private List<Integer> tagList = new ArrayList<Integer>();

    public String emtry;
    
    public DG_3_FILE(String futureuse) {
        this.emtry = futureuse;
        if(emtry != null){
            tagList.add(new Integer(EMTRY_TAG));
        }
    }

    /**
     * Constructs a new file based on data in <code>in</code>.
     * 
     * @param in
     *            the input stream to be decoded
     * 
     * @throws IOException
     *             if decoding fails
     */
    public DG_3_FILE(InputStream in) throws IOException {
        BERTLVInputStream tlvIn = new BERTLVInputStream(in);
        int tag = tlvIn.readTag();
        if (tag != FileStructure.EF_DG3_TAG) {
            throw new IllegalArgumentException("Expected EF_DG3_TAG");
        }
        isSourceConsistent = false;

        tlvIn.readLength();
        byte[] valueBytes = tlvIn.readValue();
        BERTLVObject mainObject = new BERTLVObject(tag, valueBytes);
        BERTLVObject tagsObject = mainObject.getSubObject(TAGS_TAG);

        byte[] tags = (byte[]) tagsObject.getValue();
        
       
        String tagString = Hex.bytesToHexString(tags);

        for (int i = 0; i < (tags.length / 2); i++) {
            String num = tagString.substring(i * 4, (i + 1) * 4);
            short tagNum = Hex.hexStringToShort(num);
            tagList.add(new Integer(tagNum));
            BERTLVObject o = mainObject.getSubObject(tagNum);
            byte[] value = (byte[]) o.getValue();
            switch (tagNum) {
            case EMTRY_TAG:
                emtry = new String(value);
                break;
            default:
                throw new IOException("Unexpected tag.");
            }
        }

    }

    public int getTag() {
        return EF_DG3_TAG;
    }

    public String toString() {
        return "DG3File: " + " emtry#: " + emtry ;
    }

    /**
     * Gets the BERTLV encoded version of this file.
     */
    public byte[] getEncoded() {
        if (isSourceConsistent) {
            return sourceObject.getEncoded();
        }
        try {
            Iterator<Integer> it = tagList.iterator();
            String tagValues = "";
            Vector<BERTLVObject> objs = new Vector<BERTLVObject>();
            while (it.hasNext()) {
                short tag = it.next().shortValue();
                tagValues += Hex.shortToHexString(tag);
                byte[] value = null;
                switch (tag) {
                case EMTRY_TAG:
                    value = emtry.getBytes();
                    break;
                default:
                    break;
                }
                BERTLVObject o = new BERTLVObject(tag, value);
                objs.add(o);
            }

            BERTLVObject result = new BERTLVObject(EF_DG3_TAG,
                    new BERTLVObject(TAGS_TAG, Hex.hexStringToBytes(tagValues)));

            Iterator<BERTLVObject> i = objs.iterator();
            while (i.hasNext()) {
                result.addSubObject(i.next());
            }
            result.reconstructLength();
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
            
            DG_3_FILE f = new DG_3_FILE("AAAAADSDSADSDASDSDAS");
            System.out.println(f.toString());
            //System.out.println("org0: " + Hex.bytesToHexString(testArray));
            byte[] enc = f.getEncoded();
            byte[] enc2 = f.getEncoded();
            System.out.println("enc1: " + Hex.bytesToHexString(enc));
            System.out.println("enc2: " + Hex.bytesToHexString(enc2));
            
            DG_3_FILE f1 = new DG_3_FILE(new ByteArrayInputStream(enc));
            System.out.println(f1.toString());
            
            
          
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
