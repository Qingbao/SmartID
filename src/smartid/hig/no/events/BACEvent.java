
package smartid.hig.no.events;

import java.util.EventObject;

import smartid.hig.no.services.BasicService;
import smartid.hig.no.services.SecureMessagingWrapper;

/**
 * Event to indicate BAC protocol was executed.
 * 
 *
 */
public class BACEvent extends EventObject
{	
   private static final long serialVersionUID = -5177594173285843844L;

   private BasicService service;
   private boolean success;
   private byte[] rndICC, rndIFD, kICC, kIFD;
   
   /**
    * Constructs a new event.
    * 
    * @param service event source
    * @param rndICC nonce sent by ICC
    * @param rndIFD nonce sent by IFD
    * @param kICC key material provided by ICC
    * @param kIFD key material provided by IFD
    * @param success status of protocol
    */
   public BACEvent(BasicService service,
		   byte[] rndICC, byte[] rndIFD, byte[] kICC, byte[] kIFD,
		   boolean success) {
	   super(service);
	   this.service = service;
	   this.rndICC = rndICC;
	   this.rndIFD = rndIFD;
	   this.kICC = kICC;
	   this.kIFD = kIFD;
	   this.success = success;
   }

   /**
    * Gets the resulting wrapper.
    * 
    * @return the resulting wrapper
    */
   public SecureMessagingWrapper getWrapper() {
      return service.getWrapper();
   }
	
	/**
     * Gets the status of the executed BAC protocol run.
     * 
	 * @return status of the BAC protocol run.
	 */
	public boolean isSuccess() {
		return success;
	}

    /**
     * Gets the kICC key.
     * 
     * @return the kICC key material
     */
   public byte[] getKICC() {
      return kICC;
   }
   
   /**
    * Gets the kIFD key.
    * 
    * @return the kIFD key material
    */
   public byte[] getKIFD() {
      return kIFD;
   }

   /**
    * Gets the random nonce sent by the ICC during
    * this BAP protocol run.
    * 
    * @return a random nonce
    */
   public byte[] getRndICC() {
      return rndICC;
   }

   /**
    * Gets the random nonce sent by the IFD during
    * this BAP protocol run.
    * 
    * @return a random nonce
    */
   public byte[] getRndIFD() {
      return rndIFD;
   }

   public BasicService getService() {
      return service;
   }
}
