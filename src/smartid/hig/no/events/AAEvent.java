
package smartid.hig.no.events;

import java.security.PublicKey;
import java.util.EventObject;

/**
 * Event to indicate AA protocol was executed.
 * 
 *
 */
public class AAEvent extends EventObject
{	
   private static final long serialVersionUID = 7704093568464620557L;

   private PublicKey pubkey;
   private byte[] m1;
   private byte[] m2;
   private boolean success;
   
   /**
    * Constructs a new event.
    * 
    * @param src event source
    * @param pubkey public key
    * @param m1 recoverable part
    * @param m2 nonce sent by host
    * @param success resulting status of authentication protocol
    */
   public AAEvent(Object src, PublicKey pubkey, byte[] m1, byte[] m2, boolean success) {
	  super(src);
	  this.pubkey = pubkey;
	  this.m1 = m1;
	  this.m2 = m2;
	  this.success = success;
   }

   /**
    * Gets the public key used in the protocol.
    * 
    * @return a public key
    */
	public PublicKey getPubkey() {
		return pubkey;
	}

	/**
	 * Gets m1.
	 * 
	 * @return m1
	 */
	public byte[] getM1() {
		return m1;
	}

	/**
	 * Gets m2.
	 * 
	 * @return m2.
	 */
	public byte[] getM2() {
		return m2;
	}

	/**
	 * Indicates whether the authentication protocol
	 * was successfully executed.
	 * 
	 * @return status of the protocol
	 */
	public boolean isSuccess() {
		return success;
	}
}
