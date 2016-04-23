/**
 *
 */
package smartid.hig.no.certificates;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import smartid.hig.no.utils.Files;

/**
 * The class to create a x509 certificate for signing the document, i.e. DG_SOD
 * file.
 *
 * @author Qingbao.Guo
 *
 */
public class CreateX509 {

	public static final String filenameCA = "X509/cert.der";

	public static final String filenameKey = "X509/key.der";

	public static void main(String[] args) {
		try {
			Date today = Calendar.getInstance().getTime();
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(1024);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			Date dateOfIssuing = today;
			Date dateOfExpiry = today;
			X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();
			certGenerator.setSerialNumber(new BigInteger("1"));
			certGenerator
					.setIssuerDN(new X509Name(
									"C=NO, O=HIG, OU=CSCA, CN=www.hig.no/emailAddress=qingbao.guo@hig.no"));
			certGenerator
					.setSubjectDN(new X509Name(
									"C=NO, O=HIG, OU=DSCA, CN=www.hig.no/emailAddress=qingbao.guo@hig.no"));
			certGenerator.setNotBefore(dateOfIssuing);
			certGenerator.setNotAfter(dateOfExpiry);
			certGenerator.setPublicKey(publicKey);
			certGenerator.setSignatureAlgorithm("SHA1withRSA");
			X509Certificate cert = (X509Certificate) certGenerator.generate(privateKey);

            // Get the raw data from certificates and write to default files.
			// Overwrites the files without question!!!
			byte[] CertData = cert.getEncoded();
			byte[] PrivateKeyData = privateKey.getEncoded();

			Files.writeFile(new File(filenameCA), CertData);
			Files.writeFile(new File(filenameKey), PrivateKeyData);

            // Test - read the filew again and parse its contents,
			// spit out the certificates
			X509Certificate c = Files.readCertFromFile(new File(
					filenameCA));
			System.out.println(c.toString());

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
