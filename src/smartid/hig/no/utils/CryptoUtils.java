
package smartid.hig.no.utils;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import net.sourceforge.scuba.util.Hex;



/**
 * Some static helper functions. Mostly dealing with low-level crypto.
 * 
 * 
 */
public class CryptoUtils {
    public static final int ENC_MODE = 1;

    public static final int MAC_MODE = 2;

    private CryptoUtils() {
    }

    /**
     * Derives the ENC or MAC key from the keySeed.
     * 
     * @param keySeed
     *            the key seed.
     * @param mode
     *            either <code>ENC_MODE</code> or <code>MAC_MODE</code>.
     * 
     * @return the key.
     */
    public static SecretKey deriveKey(byte[] keySeed, int mode)
            throws GeneralSecurityException {
        MessageDigest shaDigest = MessageDigest.getInstance("SHA1");
        shaDigest.update(keySeed);
        byte[] c = { 0x00, 0x00, 0x00, (byte) mode };
        shaDigest.update(c);
        byte[] hash = shaDigest.digest();
        byte[] key = new byte[24];
        System.arraycopy(hash, 0, key, 0, 8);
        System.arraycopy(hash, 8, key, 8, 8);
        System.arraycopy(hash, 0, key, 16, 8);
        SecretKeyFactory desKeyFactory = SecretKeyFactory.getInstance("DESede");
        return desKeyFactory.generateSecret(new DESedeKeySpec(key));
    }

    public static long computeSendSequenceCounter(byte[] rndICC, byte[] rndIFD) {
        if (rndICC == null || rndICC.length != 8 || rndIFD == null
                || rndIFD.length != 8) {
            throw new IllegalStateException("Wrong length input");
        }
        long ssc = 0;
        for (int i = 4; i < 8; i++) {
            ssc <<= 8;
            ssc += (long) (rndICC[i] & 0x000000FF);
        }
        for (int i = 4; i < 8; i++) {
            ssc <<= 8;
            ssc += (long) (rndIFD[i] & 0x000000FF);
        }
        return ssc;
    }

    /**
     * Pads the input <code>in</code> according to ISO9797-1 padding method 2.
     * 
     * @param in
     *            input
     * 
     * @return padded output
     */
    public static byte[] pad(byte[] in) {
        return pad(in, 0, in.length);
    }

    public static byte[] pad(byte[] in, int offset, int length) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(in, offset, length);
        out.write((byte) 0x80);
        while (out.size() % 8 != 0) {
            out.write((byte) 0x00);
        }
        return out.toByteArray();
    }

    public static byte[] unpad(byte[] in) {
        int i = in.length - 1;
        while (i >= 0 && in[i] == 0x00) {
            i--;
        }
        if ((in[i] & 0x000000FF) != 0x00000080) {
            throw new IllegalStateException(
                    "unpad expected constant 0x80, found 0x"
                            + Integer.toHexString((in[i] & 0x000000FF))
                            + "\nDEBUG: in = " + Hex.bytesToHexString(in)
                            + ", index = " + i);
        }
        byte[] out = new byte[i];
        System.arraycopy(in, 0, out, 0, i);
        return out;
    }

    /**
     * Recovers the M1 part of the message sent back by the AA protocol
     * (INTERNAL AUTHENTICATE command). The algorithm is described in ISO
     * 9796-2:2002 9.3.
     * 
     * 
     * 
     * @param digestLength
     *            should be 20
     * @param plaintext
     *            response from card, already 'decrypted' (using the AA public
     *            key)
     * 
     * @return the m1 part of the message
     */
    public static byte[] recoverMessage(int digestLength, byte[] plaintext) {
        if (plaintext == null || plaintext.length < 1) {
            throw new IllegalArgumentException(
                    "Plaintext too short to recover message");
        }
        if (((plaintext[0] & 0xC0) ^ 0x40) != 0) {
            // 0xC0 = 1100 0000, 0x40 = 0100 0000
            throw new NumberFormatException("Could not get M1");
        }
        if (((plaintext[plaintext.length - 1] & 0xF) ^ 0xC) != 0) {
            // 0xF = 0000 1111, 0xC = 0000 1100
            throw new NumberFormatException("Could not get M1");
        }
        int delta = 0;
        if (((plaintext[plaintext.length - 1] & 0xFF) ^ 0xBC) == 0) {
            delta = 1;
        } else {
            // 0xBC = 1011 1100
            throw new NumberFormatException("Could not get M1");
        }

        /* find out how much padding we've got */
        int paddingLength = 0;
        for (; paddingLength < plaintext.length; paddingLength++) {
            // 0x0A = 0000 1010
            if (((plaintext[paddingLength] & 0x0F) ^ 0x0A) == 0) {
                break;
            }
        }
        int messageOffset = paddingLength + 1;

        int paddedMessageLength = plaintext.length - delta - digestLength;
        int messageLength = paddedMessageLength - messageOffset;

        /* there must be at least one byte of message string */
        if (messageLength <= 0) {
            throw new NumberFormatException("Could not get M1");
        }

        /*
         * TODO: if we contain the whole message as well, check the hash of
         * that.
         */
        if ((plaintext[0] & 0x20) == 0) {
            throw new NumberFormatException("Could not get M1");
        } else {
            byte[] recoveredMessage = new byte[messageLength];
            System.arraycopy(plaintext, messageOffset, recoveredMessage, 0,
                    messageLength);
            return recoveredMessage;
        }
    }
  
    
}
