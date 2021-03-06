package smartid.hig.no.lds;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import net.sourceforge.scuba.tlv.BERTLVInputStream;
import net.sourceforge.scuba.util.Hex;

/**
 * File structure for contains biomatric data.
 *
 *
 */
public abstract class DG_N_FILE extends DataGroups {

	static final int BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG = 0x7F61;
	static final int BIOMETRIC_INFORMATION_TEMPLATE_TAG = 0x7F60;

	static final int BIOMETRIC_INFO_COUNT_TAG = 0x02;
	static final int BIOMETRIC_HEADER_TEMPLATE_BASE_TAG = (byte) 0xA1;
	static final int BIOMETRIC_DATA_BLOCK_TAG = 0x5F2E;
	static final int BIOMETRIC_DATA_BLOCK_TAG_ALT = 0x7F2E;

	static final int FORMAT_OWNER_TAG = 0x87;
	static final int FORMAT_TYPE_TAG = 0x88;

	/**
	 * From ISO7816-11: Secure Messaging Template tags.
	 */
	static final int SMT_TAG = 0x7D,
			SMT_DO_PV = 0x81,
			SMT_DO_CG = 0x85,
			SMT_DO_CC = 0x8E,
			SMT_DO_DS = 0x9E;

	protected List<byte[]> templates;

	protected DG_N_FILE() {
	}

	/**
	 * Constructs a new file.
	 *
	 * @param in the input stream with the file contents
	 * @param requiredTag the marking tag for this file
	 */
	public DG_N_FILE(InputStream in, int requiredTag) throws IOException {
		super(in);
		if (this.dataGroupTag != requiredTag) {
			throw new IllegalArgumentException("Expected "
					+ Hex.intToHexString(requiredTag));
		}
		try {
			BERTLVInputStream tlvIn = new BERTLVInputStream(in);
			int bioInfoGroupTemplateTag = tlvIn.readTag();
			if (bioInfoGroupTemplateTag != BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG) { /* 7F61 */

				throw new IllegalArgumentException("Expected tag BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG (" + Integer.toHexString(BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG) + ") in CBEFF structure, found " + Integer.toHexString(bioInfoGroupTemplateTag));
			}
			tlvIn.readLength();
			int bioInfoCountTag = tlvIn.readTag();
			if (bioInfoCountTag != BIOMETRIC_INFO_COUNT_TAG) { /* 02 */

				throw new IllegalArgumentException("Expected tag BIOMETRIC_INFO_COUNT_TAG (" + Integer.toHexString(BIOMETRIC_INFO_COUNT_TAG) + ") in CBEFF structure, found " + Integer.toHexString(bioInfoCountTag));
			}
			int tlvBioInfoCountLength = tlvIn.readLength();
			if (tlvBioInfoCountLength != 1) {
				throw new IllegalArgumentException("BIOMETRIC_INFO_COUNT should have length 1, found length " + tlvBioInfoCountLength);
			}
			int bioInfoCount = (tlvIn.readValue()[0] & 0xFF);
			for (int i = 0; i < bioInfoCount; i++) {
				readBIT(tlvIn, i);
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new IllegalArgumentException("Could not decode: " + e.toString());
		}
		isSourceConsistent = false;
	}

	private void readBIT(BERTLVInputStream tlvIn, int templateIndex) throws IOException {
		int bioInfoTemplateTag = tlvIn.readTag();
		if (bioInfoTemplateTag != BIOMETRIC_INFORMATION_TEMPLATE_TAG /* 7F60 */) {
			throw new IllegalArgumentException("Expected tag BIOMETRIC_INFORMATION_TEMPLATE_TAG (" + Integer.toHexString(BIOMETRIC_INFORMATION_TEMPLATE_TAG) + "), found " + Integer.toHexString(bioInfoTemplateTag));
		}
		tlvIn.readLength();

		int headerTemplateTag = tlvIn.readTag();
		int headerTemplateLength = tlvIn.readLength();

		if ((headerTemplateTag == SMT_TAG)) {
			/* The BIT is protected... */
			readStaticallyProtectedBIT(headerTemplateTag, headerTemplateLength, templateIndex, tlvIn);
		} else if ((headerTemplateTag & 0xA0) == 0xA0) {
			readBHT(headerTemplateTag, headerTemplateLength, templateIndex, tlvIn);
			readBiometricDataBlock(tlvIn);
		} else {
			throw new IllegalArgumentException("Unsupported template tag: " + Integer.toHexString(headerTemplateTag));
		}
	}

	/**
	 * A1, A2, ... Will contain DOs as described in ISO 7816-11 Annex C.
	 */
	private void readBHT(int headerTemplateTag, int headerTemplateLength, int templateIndex, BERTLVInputStream tlvIn) throws IOException {
		int expectedBioHeaderTemplateTag = (BIOMETRIC_HEADER_TEMPLATE_BASE_TAG + templateIndex) & 0xFF;
		if (headerTemplateTag != expectedBioHeaderTemplateTag) {
			String warning = "Expected tag BIOMETRIC_HEADER_TEMPLATE_TAG (" + Integer.toHexString(expectedBioHeaderTemplateTag) + "), found " + Integer.toHexString(headerTemplateTag);
			System.out.println(warning);
			// throw new IllegalArgumentException(warning);
		}
		/* We'll just skip this header for now. */
		tlvIn.skip(headerTemplateLength);
	}

	/**
	 * Reads a biometric information template protected with secure messaging.
	 * Described in ISO7816-11 Annex D.
	 *
	 * @param tag should be <code>0x7D</code>
	 * @param length the length of the BIT
	 * @param templateIndex index of the template
	 * @param tlvIn source to read from
	 *
	 * @throws IOException on failure
	 */
	private void readStaticallyProtectedBIT(int tag, int length, int templateIndex, BERTLVInputStream tlvIn) throws IOException {
		BERTLVInputStream tlvBHTIn = new BERTLVInputStream(new ByteArrayInputStream(decodeSMTValue(tlvIn)));
		int headerTemplateTag = tlvBHTIn.readTag();
		int headerTemplateLength = tlvBHTIn.readLength();
		readBHT(headerTemplateTag, headerTemplateLength, templateIndex, tlvBHTIn);
		BERTLVInputStream tlvBiometricDataBlockIn = new BERTLVInputStream(new ByteArrayInputStream(decodeSMTValue(tlvIn)));
		readBiometricDataBlock(tlvBiometricDataBlockIn);
	}

	private byte[] decodeSMTValue(BERTLVInputStream tlvIn) throws IOException {
		int doTag = tlvIn.readTag();
		int doLength = tlvIn.readLength();
		switch (doTag) {
			case SMT_DO_PV /* 0x81 */:
				/* NOTE: Plain value, just return whatever is in the payload */
				return tlvIn.readValue();
			case SMT_DO_CG /* 0x85 */:
				/* NOTE: content of payload is encrypted */
				return tlvIn.readValue();
			case SMT_DO_CC /* 0x8E */:
				/* NOTE: payload contains a MAC */
				tlvIn.skip(doLength);
			case SMT_DO_DS /* 0x9E */:
				/* NOTE: payload contains a signature */
				tlvIn.skip(doLength);
		}
		return null;
	}

	private void readBiometricDataBlock(BERTLVInputStream tlvIn) throws IOException {
		int bioDataBlockTag = tlvIn.readTag();
		if (bioDataBlockTag != BIOMETRIC_DATA_BLOCK_TAG /* 5F2E */ && bioDataBlockTag != BIOMETRIC_DATA_BLOCK_TAG_ALT /* 7F2E */) {
			throw new IllegalArgumentException("Expected tag BIOMETRIC_DATA_BLOCK_TAG (" + Integer.toHexString(BIOMETRIC_DATA_BLOCK_TAG) + ") or BIOMETRIC_DATA_BLOCK_TAG_ALT (" + Integer.toHexString(BIOMETRIC_DATA_BLOCK_TAG_ALT) + "), found " + Integer.toHexString(bioDataBlockTag));
		}
		int length = tlvIn.readLength();
		readBiometricData(tlvIn, length);
	}

	/**
	 * Reads the biometric data block. This method should be implemented by
	 * concrete subclasses (DG2 - DG4 structures). It is assumed that the caller
	 * has already read the biometric data block tag (5F2E or 7F2E) and the
	 * length.
	 *
	 * @param in the input stream positioned so that biometric data block tag
	 * and length are already read
	 * @param length the length
	 * @throws IOException if reading fails
	 */
	protected void readBiometricData(InputStream in, int length) throws IOException {
		DataInputStream dataIn = new DataInputStream(in);
		byte[] data = new byte[length];
		dataIn.readFully(data);
		if (templates == null) {
			templates = new ArrayList<byte[]>();
		}
		templates.add(data);
	}

	public int getTag() {
		return dataGroupTag;
	}

	public abstract byte[] getEncoded();

	public abstract String toString();

}
