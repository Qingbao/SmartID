/**
 * 
 */
package smartid.hig.no.lds;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import net.sourceforge.scuba.tlv.BERTLVInputStream;
import net.sourceforge.scuba.tlv.BERTLVObject;
import net.sourceforge.scuba.util.Hex;

/**
 * 
 * File structure for the EF_DG4 file.
 * 
 *
 *
 */
public class DG_4_FILE extends DataGroups{
	
	private static final short TYPE_TAG = 0x89;

    private static final short DATA_TAG = 0x5F43;

    private byte[] fingerprintData = null;

    private int imageType = 0;

    private String mimeImageType = null;

    public static final int TYPE_JPEG = 3;

    public static final int TYPE_JPEG2000 = 4;

    public static final int TYPE_WSQ = '?';

    /**
     * Constructs a new file.
     * 
     * @param data
     *            the face image raw data
     * @param mimeType
     *            the mime type of the image data
     */
    public DG_4_FILE(byte[] data, String mimeType) {
    	fingerprintData = data;
        if ("image/jpeg".equals(mimeType)) {
            imageType = TYPE_JPEG;
        } else if ("image/jpeg2000".equals(mimeType)) {
            imageType = TYPE_JPEG2000;
        } else {
            throw new IllegalArgumentException("Wrong image type.");
        }
        mimeImageType = mimeType;
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
    public DG_4_FILE(InputStream in) throws IOException {
        BERTLVInputStream tlvIn = new BERTLVInputStream(in);
        int tag = tlvIn.readTag();
        if (tag != FileStructure.EF_DG4_TAG) {
            throw new IllegalArgumentException("Expected EF_DG4_TAG");
        }
        isSourceConsistent = false;
        tlvIn.readLength();
        byte[] valueBytes = tlvIn.readValue();
        BERTLVObject mainObject = new BERTLVObject(tag, valueBytes);
        BERTLVObject typeObject = mainObject.getSubObject(TYPE_TAG);
        BERTLVObject dataObject = mainObject.getSubObject(DATA_TAG);
        imageType = ((byte[]) typeObject.getValue())[0];
        if (imageType == TYPE_JPEG) {
            mimeImageType = "image/jpeg";
        } else if (imageType == TYPE_JPEG2000) {
            mimeImageType = "image/jpeg2000";
        } else {
            throw new IOException("Wrong image type.");
        }
        fingerprintData = (byte[]) dataObject.getValue();
    }

    public int getTag() {
        return EF_DG4_TAG;
    }

    public String toString() {
        return "DG4File: type " + imageType + " bytes " + fingerprintData.length;
    }

    /**
     * Gets the mime type of the stored signature image.
     * 
     * @return the mime type of the signature image
     */
    public String getMimeType() {
        return mimeImageType;
    }

    /**
     * Gets the raw image data.
     * 
     * @return image data
     */
    public byte[] getImage() {
        return fingerprintData;
    }

    /**
     * Gets the BERTLV encoded version of this file.
     */
    public byte[] getEncoded() {
        if (isSourceConsistent) {
            return sourceObject.getEncoded();
        }
        try {
            BERTLVObject result = new BERTLVObject(EF_DG4_TAG,
                    new BERTLVObject(TYPE_TAG, new byte[] { (byte) imageType }));
            result.addSubObject(new BERTLVObject(DATA_TAG, fingerprintData));
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
            byte[] testArray = new byte[] { 0x76, 0x08, (byte) 0x89, 0x01,
                    0x03, 0x5F, 0x43, 0x02, (byte) 0xDE, (byte) 0xAD, };
            DG_4_FILE f = new DG_4_FILE(new ByteArrayInputStream(testArray));
            System.out.println(f.toString());
            System.out.println("org0: " + Hex.bytesToHexString(testArray));
            byte[] enc = f.getEncoded();
            byte[] enc2 = f.getEncoded();
            System.out.println("enc1: " + Hex.bytesToHexString(enc));
            System.out.println("enc2: " + Hex.bytesToHexString(enc2));
            System.out.println("Compare1: " + Arrays.equals(testArray, enc));
            System.out.println("Compare2: " + Arrays.equals(enc, enc2));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
