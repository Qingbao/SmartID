/**
 * 
 */
package smartid.hig.no.lds;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.TreeMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.icao.DataGroupHash;
import org.bouncycastle.asn1.icao.LDSSecurityObject;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.provider.X509CertificateObject;

import net.sourceforge.scuba.tlv.BERTLVInputStream;
import net.sourceforge.scuba.tlv.BERTLVObject;
import net.sourceforge.scuba.util.Hex;

/**
 * 
 * File structure for the EF_SOD file. This file contains the security object.
 * 
 *
 */
public class DG_SOD extends FileStructure{
	
	private static final DERObjectIdentifier ICAO_SOD_OID = new DERObjectIdentifier(
            "2.23.136.1.1.1");

    private static final DERObjectIdentifier SIGNED_DATA_OID = new DERObjectIdentifier(
            "1.2.840.113549.1.7.2");

    private static final DERObjectIdentifier RFC_3369_CONTENT_TYPE_OID = new DERObjectIdentifier(
            "1.2.840.113549.1.9.3");

    private static final DERObjectIdentifier RFC_3369_MESSAGE_DIGEST_OID = new DERObjectIdentifier(
            "1.2.840.113549.1.9.4");

    private static final DERObjectIdentifier RSA_SA_PSS_OID = new DERObjectIdentifier(
            "1.2.840.113549.1.1.10");

    private static final DERObjectIdentifier PKCS1_SHA1_WITH_RSA_OID = new DERObjectIdentifier(
            "1.2.840.113549.1.1.5");

    private static final DERObjectIdentifier PKCS1_SHA256_WITH_RSA_OID = new DERObjectIdentifier(
            "1.2.840.113549.1.1.11");
    
    private static final DERObjectIdentifier PKCS1_SHA384_WITH_RSA_OID = new DERObjectIdentifier(
            "1.2.840.113549.1.1.12");

    private static final DERObjectIdentifier PKCS1_SHA512_WITH_RSA_OID = new DERObjectIdentifier(
            "1.2.840.113549.1.1.13");

    private static final DERObjectIdentifier PKCS1_SHA224_WITH_RSA_OID = new DERObjectIdentifier(
            "1.2.840.113549.1.1.14");

    private SignedData signedData;
    
    private String sodString = "";

    /**
     * Constructs a Security Object data structure.
     * 
     * @param digestAlgorithm
     *            a digest algorithm, such as "SHA1" or "SHA256"
     * @param digestEncryptionAlgorithm
     *            a digest encryption algorithm, such as "SHA256withRSA"
     * @param dataGroupHashes
     *            maps datagroupnumbers (1 to 16) to hashes of the data groups
     * @param encryptedDigest
     *            the signature
     * @param docSigningCertificate
     *            the document signing certificate
     * 
     * @throws NoSuchAlgorithmException
     *             if either of the algorithm parameters is not recognized
     * @throws CertificateException
     *             if the document signing certificate cannot be used
     */
    public DG_SOD(String digestAlgorithm, String digestEncryptionAlgorithm,
            Map<Integer, byte[]> dataGroupHashes, byte[] encryptedDigest,
            X509Certificate docSigningCertificate)
            throws NoSuchAlgorithmException, CertificateException {
        signedData = createSignedData(digestAlgorithm,
                digestEncryptionAlgorithm, dataGroupHashes, encryptedDigest,
                docSigningCertificate);
    }

    /**
     * Constructs a Security Object data structure.
     * 
     * @param digestAlgorithm
     *            a digest algorithm, such as "SHA1" or "SHA256"
     * @param digestEncryptionAlgorithm
     *            a digest encryption algorithm, such as "SHA256withRSA"
     * @param dataGroupHashes
     *            maps datagroupnumbers (1 to 16) to hashes of the data groups
     * @param privateKey
     *            the private key to sign the data with
     * @param docSigningCertificate
     *            the document signing certificate
     * 
     * @throws NoSuchAlgorithmException
     *             if either of the algorithm parameters is not recognized
     * @throws CertificateException
     *             if the document signing certificate cannot be used
     */
    public DG_SOD(String digestAlgorithm, String digestEncryptionAlgorithm,
            Map<Integer, byte[]> dataGroupHashes, DocumentSigner signer,
            X509Certificate docSigningCertificate)
            throws NoSuchAlgorithmException, CertificateException {
        signedData = createSignedData(digestAlgorithm,
                digestEncryptionAlgorithm, dataGroupHashes, signer,
                docSigningCertificate);
    }

    /**
     * Constructs a Security Object data structure.
     * 
     * @param in
     *            some inputstream
     * @throws IOException
     *             if something goes wrong
     */
    public DG_SOD(InputStream in) throws IOException {
        BERTLVInputStream tlvIn = new BERTLVInputStream(in);
        if (tlvIn.readTag() != EF_SOD_TAG)
            throw new IOException("Wrong tag");
        tlvIn.readLength();
        ASN1InputStream asn1in = new ASN1InputStream(in);
        DERSequence seq = (DERSequence) asn1in.readObject();
        DERObjectIdentifier objectIdentifier = (DERObjectIdentifier) seq
                .getObjectAt(0);
        if (!objectIdentifier.equals(SIGNED_DATA_OID)) {
            throw new IOException("Wrong OID: " + objectIdentifier.getId());
        }
        DERTaggedObject o = (DERTaggedObject) seq.getObjectAt(1);
        /* TODO: where is this tagNo specified? */
        // int tagNo = o.getTagNo();
        DERSequence s2 = (DERSequence) o.getObject();
        this.signedData = new SignedData(s2);

    }

    /**
     * The tag of this file.
     * 
     * @return the tag
     */
    public int getTag() {
        return EF_SOD_TAG;
    }

    /**
     * Gets a BERTLV encoded form of this file.
     */
    public byte[] getEncoded() {
        if (isSourceConsistent) {
            return sourceObject.getEncoded();
        }

        /* TODO: where is that DERTaggedObject specified? */
        ASN1Encodable[] fileContents = { SIGNED_DATA_OID,
                new DERTaggedObject(0, signedData) };
        ASN1Sequence fileContentsObject = new DERSequence(fileContents);
        BERTLVObject sodFile = new BERTLVObject(EF_SOD_TAG, fileContentsObject
                .getDEREncoded(), false);
        return sodFile.getEncoded();
    }
    
  

    public String toString() {
        try {
            X509Certificate cert = getDocSigningCertificate();
            DataGroupHash[] hashObjects = getSecurityObject(signedData)
                    .getDatagroupHash();
            for (int i = 0; i < hashObjects.length; i++) {
                DataGroupHash hashObject = hashObjects[i];
                int number = hashObject.getDataGroupNumber();
                byte[] hashValue = hashObject.getDataGroupHashValue().getOctets();
                sodString+="DG: "+number+" Hash: "+Hex.bytesToHexString(hashValue)+"\n";
            }
            return "SODFile " + cert.getIssuerX500Principal()+"\n"
            		+sodString;
        } catch (Exception e) {
            return "SODFile";
        }
    }

    /**
     * Gets the stored data group hashes.
     * 
     * @return data group hashes indexed by data group numbers (1 to 16)
     */
    public Map<Integer, byte[]> getDataGroupHashes() {
        DataGroupHash[] hashObjects = getSecurityObject(signedData)
                .getDatagroupHash();
        Map<Integer, byte[]> hashMap = new TreeMap<Integer, byte[]>(); /*
                                                                         * HashMap...
                                                                         * get
                                                                         * it?
                                                                         * :D
                                                                         */
        for (int i = 0; i < hashObjects.length; i++) {
            DataGroupHash hashObject = hashObjects[i];
            int number = hashObject.getDataGroupNumber();
            byte[] hashValue = hashObject.getDataGroupHashValue().getOctets();
            hashMap.put(number, hashValue);
        }
        return hashMap;
    }

    /**
     * Gets the signature (the encrypted digest) over the hashes.
     * 
     * @return the encrypted digest
     */
    public byte[] getEncryptedDigest() {
        return getEncryptedDigest(signedData);
    }

    /**
     * Gets the name of the algorithm used in the data group hashes.
     * 
     * @return an algorithm string such as "SHA1" or "SHA256"
     */
    public String getDigestAlgorithm() {
        try {
            return lookupMnemonicByOID(getSecurityObject(signedData)
                    .getDigestAlgorithmIdentifier().getObjectId());
        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
            throw new IllegalStateException(nsae.toString());
        }
    }

    /**
     * Gets the name of the algorithm used in the signature.
     * 
     * @return an algorithm string such as "SHA256withRSA"
     */
    public String getDigestEncryptionAlgorithm() {
        try {
            return lookupMnemonicByOID(getSignerInfo(signedData)
                    .getDigestEncryptionAlgorithm().getObjectId());
        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
            throw new IllegalStateException(nsae.toString());
        }
    }

    /**
     * Gets the document signing certificate. Use this certificate to verify
     * that <i>eSignature</i> is a valid signature for <i>eContent</i>. This
     * certificate itself is signed using the country signing certificate.
     * 
     * @return the document signing certificate
     */
    public X509Certificate getDocSigningCertificate() throws IOException,
            CertificateException {
        byte[] certSpec = null;
        ASN1Set certs = signedData.getCertificates();
        if (certs.size() != 1) {
            System.err.println("WARNING: found " + certs.size()
                    + " certificates");
        }
        for (int i = 0; i < certs.size(); i++) {
            X509CertificateStructure e = new X509CertificateStructure(
                    (DERSequence) certs.getObjectAt(i));
            certSpec = new X509CertificateObject(e).getEncoded();
        }
        /*
         * NOTE: we could have just returned that X509CertificateObject here,
         * but by reconstructing it using the client's default provider we hide
         * the fact that we're using BC.
         */

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) factory
                .generateCertificate(new ByteArrayInputStream(certSpec));
        return cert;
    }

    /**
     * Verifies the signature over the contents of the security object. Clients
     * can also use the accessors of this class and check the validity of the
     * signature for themselves.
     * 
     * See RFC 3369, Cryptographic Message Syntax, August 2002, Section 5.4 for
     * details.
     * 
     * @param docSigningCert
     *            the certificate to use (should be X509 certificate)
     * 
     * @return status of the verification
     * 
     * @throws GeneralSecurityException
     *             if something goes wrong
     */
    public boolean checkDocSignature(Certificate docSigningCert)
            throws GeneralSecurityException {

        byte[] eContent = getEContent();
        byte[] signature = getEncryptedDigest(signedData);

        String encAlg = getSignerInfo(signedData)
                .getDigestEncryptionAlgorithm().getObjectId().getId();

        // For the cases where the signature is simply a digest

        if (encAlg == null) {
            String digestAlg = getSignerInfo(signedData).getDigestAlgorithm()
                    .getObjectId().getId();
            MessageDigest digest = MessageDigest.getInstance(digestAlg);
            digest.update(eContent);
            byte[] digestBytes = digest.digest();
            return Arrays.equals(digestBytes, signature);
        }

        // For the RSA_SA_PSS 1. the default hash is SHA1, 2. The hash id is not
        // encoded in OID
        // So it has to be specified "manually"
        if (encAlg.equals(RSA_SA_PSS_OID.toString())) {
            encAlg = lookupMnemonicByOID(getSignerInfo(signedData)
                    .getDigestAlgorithm().getObjectId())
                    + "withRSA/PSS";
        }

        Signature sig = Signature.getInstance(encAlg);
        sig.initVerify(docSigningCert);
        sig.update(eContent);
        return sig.verify(signature);

    }

    private static SignerInfo getSignerInfo(SignedData signedData) {
        ASN1Set signerInfos = signedData.getSignerInfos();
        if (signerInfos.size() > 1) {
            System.err.println("WARNING: found " + signerInfos.size()
                    + " signerInfos");
        }
        for (int i = 0; i < signerInfos.size(); i++) {
            SignerInfo info = new SignerInfo((DERSequence) signerInfos
                    .getObjectAt(i));
            return info;
        }
        return null;
    }

    /**
     * Reads the security object (containing the hashes of the data groups)
     * found in the SOD on the card.
     * 
     * @return the security object
     * 
     * @throws IOException
     */
    private static LDSSecurityObject getSecurityObject(SignedData signedData) {
        try {
            ContentInfo contentInfo = signedData.getEncapContentInfo();
            byte[] content = ((DEROctetString) contentInfo.getContent())
                    .getOctets();
            ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(
                    content));

            LDSSecurityObject sod = new LDSSecurityObject((DERSequence) in
                    .readObject());
            Object nextObject = in.readObject();

            if (nextObject != null) {
                System.err
                        .println("WARNING: extra object found after LDSSecurityObject...");
            }
            return sod;
        } catch (IOException ioe) {
            throw new IllegalStateException(
                    "Could not read security object in signedData");
        }
    }

    /**
     * Gets the contents of the security object over which the signature is to
     * be computed.
     * 
     * See RFC 3369, Cryptographic Message Syntax, August 2002, Section 5.4 for
     * details.
     * 
     * FIXME: Maybe throw an exception instead of issuing warnings on stderr if
     * signed attributes don't check out.
     * 
     * @see #getDocSigningCertificate()
     * @see #getSignature()
     * 
     * @return the contents of the security object over which the signature is
     *         to be computed
     */
    public byte[] getEContent() {
        SignerInfo signerInfo = getSignerInfo(signedData);
        ASN1Set signedAttributesSet = signerInfo.getAuthenticatedAttributes();

        ContentInfo contentInfo = signedData.getEncapContentInfo();
        byte[] contentBytes = ((DEROctetString) contentInfo.getContent())
                .getOctets();

        if (signedAttributesSet.size() == 0) {
            /* Signed attributes absent, return content to be signed... */
            return contentBytes;
        } else {
            /*
             * Signed attributes present (i.e. a structure containing a hash of
             * the content), return that structure to be signed...
             */
            /*
             * This option is taken by ICAO passports and assumingly by ISO18013
             * license? TODO: ?
             */
            byte[] attributesBytes = signedAttributesSet.getDEREncoded();
            String digAlg = signerInfo.getDigestAlgorithm().getObjectId()
                    .getId();
            try {
                /*
                 * We'd better check that the content actually digests to the
                 * hash value contained! ;)
                 */
                Enumeration<?> attributes = signedAttributesSet.getObjects();
                byte[] storedDigestedContent = null;
                while (attributes.hasMoreElements()) {
                    Attribute attribute = new Attribute(
                            (DERSequence) attributes.nextElement());
                    DERObjectIdentifier attrType = attribute.getAttrType();
                    if (attrType.equals(RFC_3369_MESSAGE_DIGEST_OID)) {
                        ASN1Set attrValuesSet = attribute.getAttrValues();
                        if (attrValuesSet.size() != 1) {
                            System.err
                                    .println("WARNING: expected only one attribute value in signedAttribute message digest in eContent!");
                        }
                        storedDigestedContent = ((DEROctetString) attrValuesSet
                                .getObjectAt(0)).getOctets();
                    }
                }
                if (storedDigestedContent == null) {
                    System.err
                            .println("WARNING: error extracting signedAttribute message digest in eContent!");
                }
                MessageDigest dig = MessageDigest.getInstance(digAlg);
                byte[] computedDigestedContent = dig.digest(contentBytes);
                if (!Arrays.equals(storedDigestedContent,
                        computedDigestedContent)) {
                    System.err
                            .println("WARNING: error checking signedAttribute message digest in eContent!");
                }
            } catch (NoSuchAlgorithmException nsae) {
                System.err
                        .println("WARNING: error checking signedAttribute in eContent! No such algorithm "
                                + digAlg);
            }
            return attributesBytes;
        }
    }

    /**
     * Gets the stored signature of the security object.
     * 
     * @see #getDocSigningCertificate()
     * 
     * @return the signature
     */
    private static byte[] getEncryptedDigest(SignedData signedData) {
        SignerInfo signerInfo = getSignerInfo(signedData);
        return signerInfo.getEncryptedDigest().getOctets();
    }

    private static SignedData createSignedData(String digestAlgorithm,
            String digestEncryptionAlgorithm,
            Map<Integer, byte[]> dataGroupHashes, byte[] encryptedDigest,
            X509Certificate docSigningCertificate)
            throws NoSuchAlgorithmException, CertificateException {
        ASN1Set digestAlgorithmsSet = createSingletonSet(createDigestAlgorithms(digestAlgorithm));
        ContentInfo contentInfo = createContentInfo(digestAlgorithm,
                dataGroupHashes);
        byte[] content = ((DEROctetString) contentInfo.getContent())
                .getOctets();
        ASN1Set certificates = createSingletonSet(createCertificate(docSigningCertificate));
        ASN1Set crls = null;
        ASN1Set signerInfos = createSingletonSet(createSignerInfo(
                digestAlgorithm, digestEncryptionAlgorithm, content,
                encryptedDigest, docSigningCertificate).toASN1Object());
        return new SignedData(digestAlgorithmsSet, contentInfo, certificates,
                crls, signerInfos);
    }

    private static SignedData createSignedData(String digestAlgorithm,
            String digestEncryptionAlgorithm,
            Map<Integer, byte[]> dataGroupHashes, DocumentSigner signer,
            X509Certificate docSigningCertificate)
            throws NoSuchAlgorithmException, CertificateException {
        ASN1Set digestAlgorithmsSet = createSingletonSet(createDigestAlgorithms(digestAlgorithm));
        ContentInfo contentInfo = createContentInfo(digestAlgorithm,
                dataGroupHashes);
        byte[] content = ((DEROctetString) contentInfo.getContent())
                .getOctets();

        byte[] encryptedDigest = null;
        byte[] dataToBeSigned = createAuthenticatedAttributes(
                 digestAlgorithm, content).getDEREncoded();
        // FIXME should not really be necessary
        signer.setCertificate(docSigningCertificate);
        encryptedDigest = signer.signData(dataToBeSigned);
        if(encryptedDigest == null) 
            return null;
        ASN1Set certificates = createSingletonSet(createCertificate(docSigningCertificate));
        ASN1Set crls = null;
        ASN1Set signerInfos = createSingletonSet(createSignerInfo(
                digestAlgorithm, digestEncryptionAlgorithm, content,
                encryptedDigest, docSigningCertificate).toASN1Object());
        return new SignedData(digestAlgorithmsSet, contentInfo, certificates,
                crls, signerInfos);
    }

    private static ASN1Sequence createDigestAlgorithms(String digestAlgorithm)
            throws NoSuchAlgorithmException {
        DERObjectIdentifier algorithmIdentifier = lookupOIDByMnemonic(digestAlgorithm);
        ASN1Encodable[] result = { algorithmIdentifier, new DERNull() };
        return new DERSequence(result);
    }

    private static ASN1Sequence createCertificate(X509Certificate cert)
            throws CertificateException {
        try {
            byte[] certSpec = cert.getEncoded();
            ASN1Sequence certSeq = (ASN1Sequence) (new ASN1InputStream(certSpec))
                    .readObject();
            return certSeq;
        } catch (IOException ioe) {
            throw new CertificateException(
                    "Could not construct certificate byte stream");
        }
    }

    private static ContentInfo createContentInfo(String digestAlgorithm,
            Map<Integer, byte[]> dataGroupHashes)
            throws NoSuchAlgorithmException {
        DataGroupHash[] dataGroupHashesArray = new DataGroupHash[dataGroupHashes
                .size()];
        int i = 0;
        for (int dataGroupNumber : dataGroupHashes.keySet()) {
            byte[] hashBytes = dataGroupHashes.get(dataGroupNumber);
            DataGroupHash hash = new DataGroupHash(dataGroupNumber,
                    new DEROctetString(hashBytes));
            dataGroupHashesArray[i++] = hash;
        }
        AlgorithmIdentifier digestAlgorithmIdentifier = new AlgorithmIdentifier(
                lookupOIDByMnemonic(digestAlgorithm), new DERNull());
        LDSSecurityObject sObject2 = new LDSSecurityObject(
                digestAlgorithmIdentifier, dataGroupHashesArray);
        return new ContentInfo(ICAO_SOD_OID, new DEROctetString(sObject2));
    }

    private static SignerInfo createSignerInfo(String digestAlgorithm,
            String digestEncryptionAlgorithm, byte[] content,
            byte[] encryptedDigest, X509Certificate docSigningCertificate)
            throws NoSuchAlgorithmException {
        /*
         * Get the issuer name (CN, O, OU, C) from the cert and put it in a
         * SignerIdentifier struct.
         */
        X500Principal docSignerPrincipal = ((X509Certificate) docSigningCertificate)
                .getIssuerX500Principal();
        X509Name docSignerName = new X509Name(true, docSignerPrincipal
                .getName()); // RFC 2253 format
        BigInteger serial = ((X509Certificate) docSigningCertificate)
                .getSerialNumber();
        SignerIdentifier sid = new SignerIdentifier(new IssuerAndSerialNumber(
                docSignerName, serial));

        AlgorithmIdentifier digestAlgorithmObject = new AlgorithmIdentifier(
                lookupOIDByMnemonic(digestAlgorithm), new DERNull());
        AlgorithmIdentifier digestEncryptionAlgorithmObject = new AlgorithmIdentifier(
                lookupOIDByMnemonic(digestEncryptionAlgorithm), new DERNull());

        ASN1Set authenticatedAttributes = createAuthenticatedAttributes(
                digestAlgorithm, content); // struct containing the hash of
        // content
        ASN1OctetString encryptedDigestObject = new DEROctetString(
                encryptedDigest); // this is the signature
        ASN1Set unAuthenticatedAttributes = null; // should be empty set?
        return new SignerInfo(sid, digestAlgorithmObject,
                authenticatedAttributes, digestEncryptionAlgorithmObject,
                encryptedDigestObject, unAuthenticatedAttributes);
    }

    private static ASN1Set createAuthenticatedAttributes(
            String digestAlgorithm, byte[] contentBytes)
            throws NoSuchAlgorithmException {
        MessageDigest dig = MessageDigest.getInstance(digestAlgorithm);
        byte[] digestedContentBytes = dig.digest(contentBytes);
        ASN1OctetString digestedContent = new DEROctetString(
                digestedContentBytes);
        Attribute contentTypeAttribute = new Attribute(
                RFC_3369_CONTENT_TYPE_OID, createSingletonSet(ICAO_SOD_OID));
        Attribute messageDigestAttribute = new Attribute(
                RFC_3369_MESSAGE_DIGEST_OID,
                createSingletonSet(digestedContent));
        ASN1Encodable[] result = { contentTypeAttribute.toASN1Object(),
                messageDigestAttribute.toASN1Object() };
        return new DERSet(result);
    }

    private static ASN1Set createSingletonSet(ASN1Encodable e) {
        ASN1Encodable[] result = { e };
        return new DERSet(result);
    }

    /**
     * Gets the common mnemonic string (such as "SHA1", "SHA256withRSA") given
     * an OID.
     * 
     * @param oid
     *            a BC OID
     * 
     * @throws NoSuchAlgorithmException
     *             if the provided OID is not yet supported
     */
    static String lookupMnemonicByOID(DERObjectIdentifier oid)
            throws NoSuchAlgorithmException {
        if (oid.equals(X509ObjectIdentifiers.organization)) {
            return "O";
        }
        if (oid.equals(X509ObjectIdentifiers.organizationalUnitName)) {
            return "OU";
        }
        if (oid.equals(X509ObjectIdentifiers.commonName)) {
            return "CN";
        }
        if (oid.equals(X509ObjectIdentifiers.countryName)) {
            return "C";
        }
        if (oid.equals(X509ObjectIdentifiers.stateOrProvinceName)) {
            return "ST";
        }
        if (oid.equals(X509ObjectIdentifiers.localityName)) {
            return "L";
        }
        if (oid.equals(X509ObjectIdentifiers.id_SHA1)) {
            return "SHA1";
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha224)) {
            return "SHA224";
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha256)) {
            return "SHA256";
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha384)) {
            return "SHA384";
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha512)) {
            return "SHA512";
        }
        if (oid.equals(PKCS1_SHA1_WITH_RSA_OID)) {
            return "SHA1withRSA";
        }
        if (oid.equals(PKCS1_SHA256_WITH_RSA_OID)) {
            return "SHA256withRSA";
        }
        if (oid.equals(PKCS1_SHA384_WITH_RSA_OID)) {
            return "SHA384withRSA";
        }
        if (oid.equals(PKCS1_SHA512_WITH_RSA_OID)) {
            return "SHA512withRSA";
        }
        if (oid.equals(PKCS1_SHA224_WITH_RSA_OID)) {
            return "SHA224withRSA";
        }
        throw new NoSuchAlgorithmException("Unknown OID " + oid);
    }

    static DERObjectIdentifier lookupOIDByMnemonic(String name)
            throws NoSuchAlgorithmException {
        if (name.equals("O")) {
            return X509ObjectIdentifiers.organization;
        }
        if (name.equals("OU")) {
            return X509ObjectIdentifiers.organizationalUnitName;
        }
        if (name.equals("CN")) {
            return X509ObjectIdentifiers.commonName;
        }
        if (name.equals("C")) {
            return X509ObjectIdentifiers.countryName;
        }
        if (name.equals("ST")) {
            return X509ObjectIdentifiers.stateOrProvinceName;
        }
        if (name.equals("L")) {
            return X509ObjectIdentifiers.localityName;
        }
        if (name.equals("SHA1")) {
            return X509ObjectIdentifiers.id_SHA1;
        }
        if (name.equals("SHA224")) {
            return NISTObjectIdentifiers.id_sha224;
        }
        if (name.equals("SHA256")) {
            return NISTObjectIdentifiers.id_sha256;
        }
        if (name.equals("SHA384")) {
            return NISTObjectIdentifiers.id_sha384;
        }
        if (name.equals("SHA512")) {
            return NISTObjectIdentifiers.id_sha512;
        }
        if (name.equals("SHA1withRSA")) {
            return PKCS1_SHA1_WITH_RSA_OID;
        }
        if (name.equals("SHA256withRSA")) {
            return PKCS1_SHA256_WITH_RSA_OID;
        }
        if (name.equals("SHA384withRSA")) {
            return PKCS1_SHA384_WITH_RSA_OID;
        }
        if (name.equals("SHA512withRSA")) {
            return PKCS1_SHA512_WITH_RSA_OID;
        }
        if (name.equals("SHA224withRSA")) {
            return PKCS1_SHA224_WITH_RSA_OID;
        }
        throw new NoSuchAlgorithmException("Unknown OID " + name);
    }

    // For testing only:
    public static void main(String[] args) {
        try {
            Security
                    .addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            String fileName = "terminal/examplesod.bin";
            InputStream in = new FileInputStream(new File(fileName));
            byte[] orig = new byte[in.available()];
            in.read(orig);
            System.out.println("ori0: " + Hex.bytesToHexString(orig));
            DG_SOD file = new DG_SOD(new ByteArrayInputStream(orig));
            byte[] orig1 = file.getEncoded();
            System.out.println("ori1: " + Hex.bytesToHexString(orig1));
            System.out.println("com o0 o1: " + Arrays.equals(orig, orig1));

            String digestAlgorithm = file.getDigestAlgorithm();
            String digestEncryptionAlgorithm = file
                    .getDigestEncryptionAlgorithm();
            Map<Integer, byte[]> dataGroupHashes = file.getDataGroupHashes();
            byte[] encryptedDigest = file.getEncryptedDigest();
            X509Certificate certificate = file.getDocSigningCertificate();

            DG_SOD file2 = new DG_SOD(digestAlgorithm,
                    digestEncryptionAlgorithm, dataGroupHashes,
                    encryptedDigest, certificate);
            byte[] enc = file2.getEncoded();
            System.out.println("enc1: " + Hex.bytesToHexString(enc));
            System.out.println("compare0: " + Arrays.equals(orig, enc));
            System.out.println("compare1: " + Arrays.equals(orig1, enc));

            DG_SOD file3 = new DG_SOD(new ByteArrayInputStream(enc));
            byte[] enc2 = file3.getEncoded();
            System.out.println("enc2: " + Hex.bytesToHexString(enc2));
            System.out.println("compare: " + Arrays.equals(enc, enc2));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
