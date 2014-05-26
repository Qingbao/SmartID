/**
 * 
 */
package smartid.hig.no.lds;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;

import net.sourceforge.scuba.tlv.BERTLVInputStream;
import net.sourceforge.scuba.tlv.BERTLVObject;
import net.sourceforge.scuba.util.Hex;

/**
 * File structure for the EF_COM file. This file contains the common data
 * (version and data group presence table) information
 * 
 * 
 *
 *
 */
public class DG_COM extends DataGroups{

    private static final int VERSION_LDS_TAG = 0x5F01;

    private static final int TAG_LIST_TAG = 0x5C;

    private static final int SOI_TAG = 0x86;

    private static final int IDL_VERSION = 1;

    private int majorVersion;

    private int releaseVersion;

    private List<Integer> tagList;

    private SecurityObjectIndicator[] sois;

    /**
     * Constructs a new file.
     * 
     * @param majorVersion
     *            an integer (=1)
     * @param releaseVersion
     *            an integer
     * @param tagList
     *            a list of data group tags
     * @param sois
     *            array with security object indicators
     * 
     * @throws IllegalArgumentException
     *             if the input is not well-formed
     */
    public DG_COM(int majorVersion, int releaseVersion, List<Integer> tagList,
            SecurityObjectIndicator[] sois) {
        if (tagList == null) {
            throw new IllegalArgumentException();
        }
        if (majorVersion != IDL_VERSION) {
            throw new IllegalArgumentException("Wrong major version: "
                    + majorVersion);
        }
        this.majorVersion = majorVersion;
        this.releaseVersion = releaseVersion;
        this.tagList = new ArrayList<Integer>();
        this.tagList.addAll(tagList);
        // Keep the sois array always non-null
        if (sois == null) {
            sois = new SecurityObjectIndicator[0];
        }
        this.sois = sois;
    }

    /**
     * As above, with the dafault empty security object indicator list
     * 
     * @param majorVersion
     *            an integer (=1)
     * @param releaseVersion
     *            an integer
     * @param tagList
     *            a list of ISO18013 data group tags
     */
    public DG_COM(int majorVersion, int releaseVersion, List<Integer> tagList) {
        this(majorVersion, releaseVersion, tagList, null);
    }

    /**
     * Constructs a new EF_COM file based on the encoded value in
     * <code>in</code>.
     * 
     * @param in
     *            should contain a TLV object with appropriate tag and contents
     * 
     * @throws IOException
     *             if the input could not be decoded
     */
    public DG_COM(InputStream in) throws IOException {
        BERTLVInputStream tlvIn = new BERTLVInputStream(in);
        int tag = tlvIn.readTag();

        if (tag != EF_COM_TAG) {
            throw new IOException("Wrong tag!");
        }
        tlvIn.readLength();
        byte[] valueBytes = tlvIn.readValue();

        BERTLVObject object = new BERTLVObject(tag, valueBytes);
        BERTLVObject versionObject = object.getSubObject(VERSION_LDS_TAG);
        BERTLVObject tagListObject = object.getSubObject(TAG_LIST_TAG);
        BERTLVObject soiObject = object.getSubObject(SOI_TAG);
        byte[] versionBytes = (byte[]) versionObject.getValue();
        if (versionBytes.length != 2) {
            throw new IllegalArgumentException(
                    "Wrong length of LDS version object");
        }
        majorVersion = versionBytes[0];
        releaseVersion = versionBytes[1];
        byte[] tagBytes = (byte[]) tagListObject.getValue();
        tagList = new ArrayList<Integer>();
        for (int i = 0; i < tagBytes.length; i++) {
            int dgTag = (tagBytes[i] & 0xFF);
            tagList.add(dgTag);
        }
        if (soiObject != null) {
            byte[] soiBytes = (byte[]) soiObject.getValue();
            ASN1InputStream input = new ASN1InputStream(soiBytes);
            DERSet set = (DERSet) input.readObject();
            sois = new SecurityObjectIndicator[set.size()];
            for (int i = 0; i < set.size(); i++) {
                DERSequence s = (DERSequence) set.getObjectAt(i);
                SecurityObjectIndicator tmp = new SecurityObjectIndicator(s);
                // We have specific implementations for DG14 & DG15 security
                // object indicators:
                if (tmp.getDGNumber() == 15) {
                    sois[i] = new SecurityObjectIndicatorDG15(s);
                } else if (tmp.getDGNumber() == 14) {
                    sois[i] = new SecurityObjectIndicatorDG14(s);
                } else {
                    sois[i] = tmp;
                }
            }
        } else {
            sois = new SecurityObjectIndicator[0];
        }
    }

    /**
     * The tag byte of this file.
     * 
     * @return the tag
     */
    public int getTag() {
        return EF_COM_TAG;
    }

    /**
     * Gets the LDS version as a dot seperated string containing version and
     * update level.
     * 
     * @return a string of the form "aa.bb"
     */
    public String getVersion() {
        return majorVersion + "." + releaseVersion;
    }

    /**
     * Gets the datagroup tags as a list of bytes.
     * 
     * @return a list of bytes
     */
    public List<Integer> getTagList() {
        return tagList;
    }

    /**
     * Inserts a tag in a proper place if not already present.
     * It is the clients responsibility to make sure the tags are 
     * sorted according to the DG number. 
     * 
     * @param tag
     */
    public void insertTag(Integer tag) {
        if (tagList.contains(tag)) {
            return;
        }
        tagList.add(tag);
    }

    /**
     * Gets the list of security object indicators stored in this object.
     * 
     * @return
     */
    public SecurityObjectIndicator[] getSOIArray() {
        return sois;
    }

    /**
     * Sets the security object indicator list.
     * 
     * @param sois the new security object indicator list
     */
    public void setSOIArray(SecurityObjectIndicator[] sois) {
        this.sois = sois;
    }

    
    /**
     * Gets the encoded representation of this COM file.
     */
    public byte[] getEncoded() {
        try {
            byte[] versionBytes = new byte[] { (byte) majorVersion,
                    (byte) releaseVersion };
            BERTLVObject versionObject = new BERTLVObject(VERSION_LDS_TAG,
                    versionBytes);
            byte[] tagListAsBytes = new byte[tagList.size()];
            for (int i = 0; i < tagList.size(); i++) {
                int dgTag = tagList.get(i);
                tagListAsBytes[i] = (byte) dgTag;
            }
            BERTLVObject tagListObject = new BERTLVObject(TAG_LIST_TAG,
                    tagListAsBytes);
            BERTLVObject[] value = null;
            if (sois == null || sois.length == 0) {
                value = new BERTLVObject[] { versionObject, tagListObject };
            } else {
                DERSequence[] soisArray = new DERSequence[sois.length];
                for (int i = 0; i < sois.length; i++) {
                    soisArray[i] = sois[i].getDERSequence();
                }
                value = new BERTLVObject[] {
                        versionObject,
                        tagListObject,
                        new BERTLVObject(SOI_TAG, new DERSet(soisArray)
                                .getEncoded()) };
            }
            BERTLVObject result = new BERTLVObject(EF_COM_TAG, value);
            result.reconstructLength();
            return result.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String toString() {
        StringBuffer result = new StringBuffer();
        result.append("COMFile: ");
        result.append("Version " + majorVersion + "." + releaseVersion);
        result.append(", ");
        int i = 0;
        result.append("[");
        int dgCount = tagList.size();
        for (int tag : tagList) {
            result.append("DG"
                    + FileStructure.lookupDataGroupNumberByTag(tag));
            if (i < dgCount - 1) {
                result.append(", ");
            }
            i++;
        }
        result.append("]");
        for (SecurityObjectIndicator soi : sois) {
            result.append(" " + soi.toString()+"\n");
        }
        return result.toString();
    }

    /**
     * Gets the list of data groups numbers (not tags!) listed in this COM file.
     * 
     * @return the list of data groups numbers
     */
    public List<Integer> getDGNumbers() {
        List<Integer> r = new ArrayList<Integer>();
        for (int tag : tagList) {
            r.add(new Integer(FileStructure
                    .lookupDataGroupNumberByTag(tag)));
        }
        return r;

    }

    // For testing only:
    public static void main(String[] args) {
        try {
            byte[] testArray = new byte[] { 0x60, 0x0c, 0x5F, 0x01, 0x02, 0x01,
                    0x00, 0x5C, 0x05, 0x61, 0x75, 0x63, 0x6E, 0x6F };
            DG_COM f = new DG_COM(new ByteArrayInputStream(testArray));
            System.out.println(f.toString());
            byte[] enc = f.getEncoded();
            byte[] enc2 = f.getEncoded();
            System.out.println("org0: " + Hex.bytesToHexString(testArray));
            System.out.println("enc1: " + Hex.bytesToHexString(enc));
            System.out.println("enc2: " + Hex.bytesToHexString(enc2));
            System.out.println("Compare1: " + Arrays.equals(testArray, enc));
            System.out.println("Compare2: " + Arrays.equals(enc, enc2));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
