
package smartid.hig.no.certificates;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.cvc.AccessRight;
import org.ejbca.cvc.AuthorizationRole;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;

import smartid.hig.no.utils.Files;


/**
 * A class for generating card verifiable certificates
 * Uses the modified org.ejbca.cvc library. The files are written to
 * the predefined files, see below.

 * 
 */
public class TerminalCertificateGenerator {

    public static final String filenameCA = "terminal/cacert.cvcert";

    public static final String filenameTerminal = "terminal/hig_terminal/terminalcert.cvcert";

    public static final String filenameKey = "terminal/hig_terminal/terminalkey.der";

    public static void main(String[] args) {
        try {
            // Install BC as security provider
            Security.addProvider(new BouncyCastleProvider());

            // Get the current time, and +3 months
            Calendar cal1 = Calendar.getInstance();
            Date validFrom = cal1.getTime();

            Calendar cal2 = Calendar.getInstance();
            cal2.add(Calendar.MONTH, 3);
            Date validTo = cal2.getTime();

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
            SecureRandom random = new SecureRandom();
            keyGen.initialize(1024, random);

            // Create a new key pair for the self signed CA certificate
            KeyPair caKeyPair = keyGen.generateKeyPair();

            // Create a new key pair for the terminal certificate (signed by CA)
            keyGen.initialize(1024, random);
            KeyPair terminalKeyPair = keyGen.generateKeyPair();

            CAReferenceField caRef = new CAReferenceField("NO", "MYID-CVCA",
                    "00001");
            HolderReferenceField holderRef = new HolderReferenceField(caRef
                    .getCountry(), caRef.getMnemonic(), caRef.getSequence());

            // Create the CA certificate
            CVCertificate caCvc = CertificateGenerator.createCertificate(
                    caKeyPair.getPublic(), caKeyPair.getPrivate(),
                    "SHA1WithRSA", caRef, holderRef, new AuthorizationRole(
                            AuthorizationRole.TRUST_ROOT, 2), new AccessRight(
                            AccessRight.DG3 | AccessRight.DG4), validFrom,
                    validTo, "BC");

            // Create the terminal certificate
            HolderReferenceField terminalHolderRef = new HolderReferenceField(
                    "NO", "RUID-CVCT", "00001");

            CVCertificate terminalCvc = CertificateGenerator.createCertificate(
                    terminalKeyPair.getPublic(), caKeyPair.getPrivate(),
                    "SHA1WithRSA", caRef, terminalHolderRef,
                    new AuthorizationRole(), new AccessRight(AccessRight.ALL),
                    validFrom, validTo, "BC");

            // Get the raw data from certificates and write to default files.
            // Overwrites the files without question!!!
            byte[] caCertData = caCvc.getDEREncoded();
            byte[] terminalCertData = terminalCvc.getDEREncoded();
            byte[] terminalPrivateKey = terminalKeyPair.getPrivate()
                    .getEncoded();

            Files.writeFile(new File(filenameCA), caCertData);
            Files.writeFile(new File(filenameTerminal), terminalCertData);
            Files.writeFile(new File(filenameKey), terminalPrivateKey);

            // Test - read the file again and parse its contents,
            // spit out the certificates

            CVCertificate c = Files.readCVCertificateFromFile(new File(
                    filenameCA));
            System.out.println(c.getCertificateBody().getAsText());

            c = Files.readCVCertificateFromFile(new File(filenameTerminal));
            System.out.println(c.getCertificateBody().getAsText());

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
