package smartid.hig.no.certificates;

import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateParser;

/**
 * Stores terminal CV certificate and keys.
 *
 * TODO: make proper error handling
 *
 */
public class TerminalCVCertificateDirectory {

	private static TerminalCVCertificateDirectory instance = null;

	private TerminalCVCertificateDirectory() {
	}

	public static TerminalCVCertificateDirectory getInstance() {
		if (instance == null) {
			instance = new TerminalCVCertificateDirectory();
		}
		return instance;
	}

	private Map<String, List<CVCertificate>> certificateListsMap = new HashMap<String, List<CVCertificate>>();

	private Map<String, PrivateKey> keysMap = new HashMap<String, PrivateKey>();

	public void addEntry(String caReference,
			List<CVCertificate> terminalCertificates, PrivateKey terminalKey) {
		if (caReference == null || certificateListsMap.containsKey(caReference)) {
			// For now we disallow this.
			throw new IllegalArgumentException(
					"Bad key (already present or null).");
		}
		if (terminalCertificates == null || terminalKey == null
				|| terminalCertificates.size() == 0) {
			throw new IllegalArgumentException();
		}
		List<CVCertificate> list = new ArrayList<CVCertificate>();
		list.addAll(terminalCertificates);
		certificateListsMap.put(caReference, list);
		keysMap.put(caReference, terminalKey);
	}

	public void scanOneDirectory(File f) throws IOException {
		if (!f.isDirectory()) {
			throw new IllegalArgumentException("File " + f.getAbsolutePath()
					+ " is not a directory.");
		}
		File[] certFiles = f.listFiles(new FileFilter() {
			public boolean accept(File pathname) {
				if (pathname.isFile()
						&& pathname.getName().startsWith("terminalcert")
						&& pathname.getName().endsWith(".cvcert")) {
					return true;
				}
				return false;
			}
		});
		File[] keyFiles = f.listFiles(new FileFilter() {
			public boolean accept(File pathname) {
				if (pathname.isFile()
						&& pathname.getName().equals("terminalkey.der")) {
					return true;
				}
				return false;
			}
		});
		certFiles = sortFiles(certFiles);
		List<CVCertificate> terminalCertificates = new ArrayList<CVCertificate>();
		String keyAlgName = "RSA";
		for (File file : certFiles) {
			System.out.println("Found certificate file: " + file);
			CVCertificate c = readCVCertificateFromFile(file);
			if (c == null) {
				throw new IOException();
			}
			terminalCertificates.add(c);
			try {
				keyAlgName = c.getCertificateBody().getPublicKey()
						.getAlgorithm();
			} catch (NoSuchFieldException nsfe) {
			}
		}
		if (keyFiles.length != 1) {
			throw new IOException();
		}
		System.out.println("Found key file: " + keyFiles[0]);
		PrivateKey k = readKeyFromFile(keyFiles[0], keyAlgName);
		if (k == null) {
			throw new IOException();
		}
		try {
			String ref = terminalCertificates.get(0).getCertificateBody()
					.getAuthorityReference().getConcatenated();
			addEntry(ref, terminalCertificates, k);
		} catch (Exception e) {
			throw new IOException();
		}
	}

	public void scanDirectory(File dir) throws IOException {
		if (!dir.isDirectory()) {
			throw new IllegalArgumentException("File " + dir.getAbsolutePath()
					+ " is not a directory.");
		}
		File[] dirs = dir.listFiles(new FileFilter() {
			public boolean accept(File pathname) {
				return pathname.isDirectory();
			}
		});
		try {
			for (File f : dirs) {
				scanOneDirectory(f);
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new IOException();
		}
	}

	public List<CVCertificate> getCertificates(String key) {
		return certificateListsMap.get(key);
	}

	public PrivateKey getPrivateKey(String key) {
		return keysMap.get(key);
	}

	public Set<String> getKeys() {
		return certificateListsMap.keySet();
	}

	private static File[] sortFiles(File[] files) {
		List<File> l = new ArrayList<File>();
		for (File f : files) {
			l.add(f);
		}
		Comparator<File> c = new Comparator<File>() {
			public int compare(File o1, File o2) {
				return o1.getName().compareTo(o2.getName());
			}
		};
		Collections.sort(l, c);
		l.toArray(files);
		return files;
	}

	private static byte[] loadFile(File file) throws IOException {
		byte[] dataBuffer = null;
		FileInputStream inStream = null;
		try {
			// Simple file loader...
			int length = (int) file.length();
			dataBuffer = new byte[length];
			inStream = new FileInputStream(file);

			int offset = 0;
			int readBytes = 0;
			boolean readMore = true;
			while (readMore) {
				readBytes = inStream.read(dataBuffer, offset, length - offset);
				offset += readBytes;
				readMore = readBytes > 0 && offset != length;
			}
		} finally {
			try {
				if (inStream != null) {
					inStream.close();
				}
			} catch (IOException e1) {
				System.out.println("loadFile - error when closing: " + e1);
			}
		}
		return dataBuffer;
	}

	private static CVCertificate readCVCertificateFromFile(File f) {
		try {
			byte[] data = loadFile(f);
			CVCObject parsedObject = CertificateParser.parseCertificate(data);
			CVCertificate c = (CVCertificate) parsedObject;
			return c;
		} catch (Exception e) {
			return null;
		}

	}

	private static PrivateKey readKeyFromFile(File f, String algName) {
		try {
			byte[] data = loadFile(f);
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(data);
			KeyFactory gen = KeyFactory.getInstance(algName);
			return gen.generatePrivate(spec);
		} catch (Exception e) {
			return null;
		}

	}

}
