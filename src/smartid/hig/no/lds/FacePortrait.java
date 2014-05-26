
package smartid.hig.no.lds;

import java.io.IOException;
import java.io.InputStream;

import net.sourceforge.scuba.tlv.BERTLVInputStream;
import net.sourceforge.scuba.tlv.BERTLVObject;
import net.sourceforge.scuba.util.Hex;

/**
 * Encapsulates a face portrait stored on the card. Stores raw image
 * data, the mime type of the image, and the time stamp.
 * 
 * 
 */
public class FacePortrait {

    public final int TYPE_JPEG = 3;

    public final int TYPE_JPEG2000 = 4;

    public final int TYPE_WSQ = '?';

    private final short INSTANCE_TAG = 0xA2;

    private final short TIME_TAG = 0x88;

    private final short TYPE_TAG = 0x89;

    private final short DATA_TAG = 0x5F40;

    private byte[] portraitContents = null;

    private String mimeImageType = null;

    private int imageType = 0;

    private String timeStamp = null;

    /**
     * Creates a new face portrait.
     * 
     * @param portraitContents
     *            raw portrait contents
     * @param mimeType
     *            the mime type of the image
     * @param time
     *            the time stamp string
     */
    public FacePortrait(byte[] portraitContents, String mimeType, String time) {
        if ("image/jpeg".equals(mimeType)) {
            imageType = TYPE_JPEG;
        } else if ("image/jpeg2000".equals(mimeType)) {
            imageType = TYPE_JPEG2000;
        } else {
            throw new IllegalArgumentException("Wrong image type.");
        }
        mimeImageType = mimeType;
        if (time == null) {
            timeStamp = "000000";
        } else {
            timeStamp = time;
        }
        this.portraitContents = portraitContents;

    }

    /**
     * Creates a new face portrait based on the data stored in <code>in</code>.
     * 
     * @param in
     *            the input stream with the data to be decoded.
     * @throws IOException
     *             on error.
     */
    public FacePortrait(InputStream in) throws IOException {
        BERTLVInputStream tlvIn = new BERTLVInputStream(in);
        int tag = tlvIn.readTag();
        if (tag != INSTANCE_TAG) {
            throw new IllegalArgumentException("Expected INSTANCE_TAG");
        }
        tlvIn.readLength();

        byte[] valueBytes = tlvIn.readValue();
        BERTLVObject mainObject = new BERTLVObject(tag, valueBytes);

        BERTLVObject timeObj = mainObject.getSubObject(TIME_TAG);
        BERTLVObject typeObj = mainObject.getSubObject(TYPE_TAG);
        BERTLVObject dataObj = mainObject.getSubObject(DATA_TAG);

        byte[] value = (byte[]) timeObj.getValue();
        timeStamp = Hex.bytesToHexString(value);
        imageType = ((byte[]) typeObj.getValue())[0];
        if (imageType == TYPE_JPEG) {
            mimeImageType = "image/jpeg";
        } else if (imageType == TYPE_JPEG2000) {
            mimeImageType = "image/jpeg2000";
        } else {
            throw new IOException("Wrong image type.");
        }
        portraitContents = (byte[]) dataObj.getValue();

    }

    /**
     * Gets a BERTLV encoding of this portrait.
     * 
     * @return BERTLV encoded object for this portrait
     */
    public BERTLVObject getTLVObject() {
        BERTLVObject result = new BERTLVObject(INSTANCE_TAG, new BERTLVObject(
                TIME_TAG, Hex.hexStringToBytes(timeStamp)));
        result.addSubObject(new BERTLVObject(TYPE_TAG,
                new byte[] { (byte) imageType }));
        result.addSubObject(new BERTLVObject(DATA_TAG, portraitContents));
        result.reconstructLength();
        return result;
    }

    /**
     * Gets a BERTLV encoding of this portrait.
     * 
     * @return BERTLV encoded data for this portrait
     */
    public byte[] getEncoded() {
        return getTLVObject().getEncoded();
    }

    /**
     * Gets the raw portrait contents.
     * 
     * @return the portrait contents.
     */
    public byte[] getImage() {
        return portraitContents;
    }

    /**
     * Gets the mime type of the image data.
     * 
     * @return the mime type of the image data.
     */
    public String getMimeType() {
        return mimeImageType;
    }

    /**
     * Gets the date stamp of the image.
     * 
     * @return the date stamp of the image.
     */
    public String getDate() {
        return timeStamp;
    }

}
