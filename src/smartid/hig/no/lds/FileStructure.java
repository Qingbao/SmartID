/**
 *
 */
package smartid.hig.no.lds;

import smartid.hig.no.services.BasicService;
import net.sourceforge.scuba.tlv.BERTLVObject;

/**
 * File structure
 *
 * @author Qingbao.Guo
 *
 */
public abstract class FileStructure {

	public static final int EF_COM_TAG = 0x60, EF_DG1_TAG = 0x61,
			EF_DG2_TAG = 0x75, EF_DG3_TAG = 0x63, EF_DG4_TAG = 0x76,
			EF_DG5_TAG = 0x65, EF_DG6_TAG = 0x66, EF_DG7_TAG = 0x67,
			EF_DG8_TAG = 0x68, EF_DG9_TAG = 0x69, EF_DG10_TAG = 0x6A,
			EF_DG11_TAG = 0x6B, EF_DG12_TAG = 0x6C, EF_DG13_TAG = 0x6D,
			EF_DG14_TAG = 0x6E, EF_DG15_TAG = 0x6F, EF_DG16_TAG = 0x70,
			EF_SOD_TAG = 0x77;

	/*
	 * We're using a dual representation with a "dirty-bit": When the DG is read
	 * from a card we need to store the binary information as-is
	 * since our constructed getEncoded() method might not (but actually should)
	 * result in exactly the same byte[] (messing up any cryptographic hash
	 * computations needed to validate the security object).
	 */
	BERTLVObject sourceObject;

	boolean isSourceConsistent;

	/**
	 * Constructor only visible to the other classes in this package.
	 */
	FileStructure() {
	}

	/**
	 * Gets the contents of this file as byte array, includes the tag and
	 * length.
	 *
	 * @return a byte array containing the file
	 */
	public abstract byte[] getEncoded();

	/**
	 *
	 *
	 * @param tag the first byte of the EF.
	 *
	 * @return the file identifier.
	 */
	public static short lookupFIDByTag(int tag) {
		switch (tag) {
			case EF_COM_TAG:
				return BasicService.EF_COM;
			case EF_DG1_TAG:
				return BasicService.EF_DG1;
			case EF_DG2_TAG:
				return BasicService.EF_DG2;
			case EF_DG3_TAG:
				return BasicService.EF_DG3;
			case EF_DG4_TAG:
				return BasicService.EF_DG4;
			case EF_DG5_TAG:
				return BasicService.EF_DG5;
			case EF_DG6_TAG:
				return BasicService.EF_DG6;
			case EF_DG7_TAG:
				return BasicService.EF_DG7;
			case EF_DG8_TAG:
				return BasicService.EF_DG8;
			case EF_DG9_TAG:
				return BasicService.EF_DG9;
			case EF_DG10_TAG:
				return BasicService.EF_DG10;
			case EF_DG11_TAG:
				return BasicService.EF_DG11;
			case EF_DG12_TAG:
				return BasicService.EF_DG12;
			case EF_DG13_TAG:
				return BasicService.EF_DG13;
			case EF_DG14_TAG:
				return BasicService.EF_DG14;
			case EF_DG15_TAG:
				return BasicService.EF_DG15;
			case EF_DG16_TAG:
				return BasicService.EF_DG16;
			case EF_SOD_TAG:
				return BasicService.EF_SOD;
			default:
				throw new NumberFormatException("Unknown tag "
						+ Integer.toHexString(tag));
		}
	}

	/**
	 *
	 *
	 * @param tag the first byte of the EF.
	 *
	 * @return the file identifier.
	 */
	public static byte lookupSIDByTag(int tag) {
		switch (tag) {
			case EF_COM_TAG:
				return BasicService.SF_COM;
			case EF_DG1_TAG:
				return BasicService.SF_DG1;
			case EF_DG2_TAG:
				return BasicService.SF_DG2;
			case EF_DG3_TAG:
				return BasicService.SF_DG3;
			case EF_DG4_TAG:
				return BasicService.SF_DG4;
			case EF_DG5_TAG:
				return BasicService.SF_DG5;
			case EF_DG6_TAG:
				return BasicService.SF_DG6;
			case EF_DG7_TAG:
				return BasicService.SF_DG7;
			case EF_DG8_TAG:
				return BasicService.SF_DG8;
			case EF_DG9_TAG:
				return BasicService.SF_DG9;
			case EF_DG10_TAG:
				return BasicService.SF_DG10;
			case EF_DG11_TAG:
				return BasicService.SF_DG11;
			case EF_DG12_TAG:
				return BasicService.SF_DG12;
			case EF_DG13_TAG:
				return BasicService.SF_DG13;
			case EF_DG14_TAG:
				return BasicService.SF_DG14;
			case EF_DG15_TAG:
				return BasicService.SF_DG15;
			case EF_DG16_TAG:
				return BasicService.SF_DG16;
			case EF_SOD_TAG:
				return BasicService.SF_SOD;
			default:
				throw new NumberFormatException("Unknown tag "
						+ Integer.toHexString(tag));
		}
	}

	/**
	 * Gets a data group number for a given tag.
	 *
	 * @param tag the tag of a data group
	 * @return the number
	 */
	public static int lookupDataGroupNumberByTag(int tag) {
		switch (tag) {
			case EF_DG1_TAG:
				return 1;
			case EF_DG2_TAG:
				return 2;
			case EF_DG3_TAG:
				return 3;
			case EF_DG4_TAG:
				return 4;
			case EF_DG5_TAG:
				return 5;
			case EF_DG6_TAG:
				return 6;
			case EF_DG7_TAG:
				return 7;
			case EF_DG8_TAG:
				return 8;
			case EF_DG9_TAG:
				return 9;
			case EF_DG10_TAG:
				return 10;
			case EF_DG11_TAG:
				return 11;
			case EF_DG12_TAG:
				return 12;
			case EF_DG13_TAG:
				return 13;
			case EF_DG14_TAG:
				return 14;
			case EF_DG15_TAG:
				return 15;
			case EF_DG16_TAG:
				return 16;
			default:
				throw new NumberFormatException("Unknown tag "
						+ Integer.toHexString(tag));
		}
	}

	/**
	 * Gets a data group number for a given file identifier.
	 *
	 * @param fid the file identifier
	 * @return the number
	 */
	public static int lookupDataGroupNumberByFID(short fid) {
		switch (fid) {
			case BasicService.EF_DG1:
				return 1;
			case BasicService.EF_DG2:
				return 2;
			case BasicService.EF_DG3:
				return 3;
			case BasicService.EF_DG4:
				return 4;
			case BasicService.EF_DG5:
				return 5;
			case BasicService.EF_DG6:
				return 6;
			case BasicService.EF_DG7:
				return 7;
			case BasicService.EF_DG8:
				return 8;
			case BasicService.EF_DG9:
				return 9;
			case BasicService.EF_DG10:
				return 10;
			case BasicService.EF_DG11:
				return 11;
			case BasicService.EF_DG12:
				return 12;
			case BasicService.EF_DG13:
				return 13;
			case BasicService.EF_DG14:
				return 14;
			case BasicService.EF_DG15:
				return 15;
			case BasicService.EF_DG16:
				return 16;
			default:
				return -1;
		}
	}

	/**
	 * Gets a tag for a given data group number
	 *
	 * @param num number of the data group
	 * @return associated tag
	 */
	public static int lookupTagByDataGroupNumber(int num) {
		switch (num) {
			case 1:
				return EF_DG1_TAG;
			case 2:
				return EF_DG2_TAG;
			case 3:
				return EF_DG3_TAG;
			case 4:
				return EF_DG4_TAG;
			case 5:
				return EF_DG5_TAG;
			case 6:
				return EF_DG6_TAG;
			case 7:
				return EF_DG7_TAG;
			case 8:
				return EF_DG8_TAG;
			case 9:
				return EF_DG9_TAG;
			case 10:
				return EF_DG10_TAG;
			case 11:
				return EF_DG11_TAG;
			case 12:
				return EF_DG12_TAG;
			case 13:
				return EF_DG13_TAG;
			case 14:
				return EF_DG14_TAG;
			case 15:
				return EF_DG15_TAG;
			case 16:
				return EF_DG16_TAG;
			default:
				throw new NumberFormatException("Unknown DG" + num);
		}
	}

}
