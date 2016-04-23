package smartid.hig.no.gui;

import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.swing.BorderFactory;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;

import net.sourceforge.scuba.smartcards.APDUEvent;
import net.sourceforge.scuba.smartcards.APDUListener;
import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.util.Hex;

import javax.smartcardio.*;

import smartid.hig.no.lds.DG_14_FILE;
import smartid.hig.no.lds.DG_15_FILE;
import smartid.hig.no.lds.DG_1_FILE;
import smartid.hig.no.lds.DG_2_FILE;
import smartid.hig.no.lds.DG_3_FILE;
import smartid.hig.no.lds.DG_4_FILE;
import smartid.hig.no.lds.DG_COM;
import smartid.hig.no.lds.DG_SOD;
import smartid.hig.no.lds.FileStructure;
import smartid.hig.no.lds.SecurityObjectIndicator;
import smartid.hig.no.services.BasicInfo;
import smartid.hig.no.services.BasicService;
import smartid.hig.no.services.SmartID;
import smartid.hig.no.utils.Files;
import smartid.hig.no.utils.GUIutil;

/**
 * A simple GUI application to read out SmartID card. Which has the following
 * characteristics: DG1, DG2 (EAC protected), DG3, DG4 (EAC protected), DG15
 * (Active Authentication), DG14 (Chip Authentication). DGCOM AND DGSOD
 *
 *
 *
 */
public class Reader extends JFrame implements ActionListener, APDUListener {

	// Constants for handling input events:
	private static final String SAVEPICTURE = "savepicture";

	private static final String SAVEID = "saveid";

	private static final String VIEWDOCCERT = "viewdoccert";

	private static final String VIEWAAKEY = "viewaakey";

	private static final String VIEWEACKEYS = "vieweackeys";

	private static final String NONE = "<NONE>";

	// Whole bunch of GUI elements:
	private DataPanel DataPanel = null;

	private JTabbedPane picturesPane = null;

	private JTextArea securityInfo;

	private JTextArea comContents;

	private JMenuItem savePicture;

	private JMenuItem saveSmartIDcard;

	private JMenuItem viewDocCert;

	private JMenuItem viewAAKey;

	private JMenuItem viewEACKeys;

	private JMenuItem exitItem;

	private JMenuItem aboutItem;

	private SecurityStatusBar statusBar;

	private DG_1_FILE dg1file = null;

	private DG_2_FILE dg2file = null;

	private DG_3_FILE dg3file = null;

	private DG_4_FILE dg4file = null;

	private DG_14_FILE dg14file = null;

	private DG_15_FILE dg15file = null;

	private DG_SOD sodFile = null;

	private DG_COM comFile = null;

	private SmartID smartID = null;

	private boolean debug = true;

	/**
	 * Log the APDU exchanges.
	 */
	public void exchangedAPDU(APDUEvent apduEvent) {
		CommandAPDU c = apduEvent.getCommandAPDU();
		ResponseAPDU r = apduEvent.getResponseAPDU();
		if (debug) {
			System.out.println("C: " + Hex.bytesToHexString(c.getBytes()));
			System.out.println("R: " + Hex.bytesToHexString(r.getBytes()));
		}
	}

	/**
	 * Construct the main GUI frame.
	 */
	public Reader() {
		super("SmartID card Reader");
		setLayout(new BorderLayout());

		JTabbedPane tabbedPane = new JTabbedPane();

		Vector<InputField> inputs = new Vector<InputField>();

		inputs.add(new InputField("sur", "Surname", new FieldFormat(
				FieldFormat.LETTERS, 0, 20), FieldGroup.Data));
		inputs.add(new InputField("given", "Given names", new FieldFormat(
				FieldFormat.LETTERS, 0, 40), FieldGroup.Data));
		inputs.add(new InputField("gender", "Gender", new FieldFormat(
				FieldFormat.LETTERS, 1, 1), FieldGroup.Data));
		inputs.add(new InputField("dob", "Date of birth(yyyymmdd)",
				new FieldFormat(FieldFormat.DIGITS, 8, 8), FieldGroup.Data));
		inputs.add(new InputField("pob", "Place of birth", new FieldFormat(
				FieldFormat.SYMBOL | FieldFormat.LETTERS | FieldFormat.DIGITS,
				0, 40), FieldGroup.Data));
		inputs.add(new InputField("issue", "Data of issue(yyyymmdd)",
				new FieldFormat(FieldFormat.DIGITS, 8, 8), FieldGroup.Data));
		inputs.add(new InputField("expriy", "Data of expriy(yyyymmdd)",
				new FieldFormat(FieldFormat.DIGITS, 8, 8), FieldGroup.Data));
		inputs.add(new InputField("country", "Issuing Country)",
				new FieldFormat(FieldFormat.LETTERS, 3, 3), FieldGroup.Data));
		inputs.add(new InputField("authority", "Issuing Authority",
				new FieldFormat(FieldFormat.SYMBOL | FieldFormat.LETTERS
						| FieldFormat.DIGITS, 0, 40), FieldGroup.Data));
		inputs.add(new InputField("id", "Personal number", new FieldFormat(
				FieldFormat.DIGITS, 11, 11), FieldGroup.Data));

		inputs.add(new InputField("emtry", "For future use", new FieldFormat(
				FieldFormat.SYMBOL | FieldFormat.LETTERS | FieldFormat.DIGITS,
				0, 25), FieldGroup.extraData));

		InputField[] ins = new InputField[inputs.size()];
		int i = 0;
		Iterator<InputField> it = inputs.iterator();
		while (it.hasNext()) {
			ins[i++] = it.next();
		}

		// basic data:
		DataPanel = new DataPanel(this, ins, false);

		// Picture
		picturesPane = new JTabbedPane();

		JPanel picPanel = new JPanel();
		picPanel.setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.gridwidth = 2;
		c.fill = GridBagConstraints.HORIZONTAL;
		c.insets = new Insets(5, 5, 5, 5);
		picPanel.add(picturesPane, c);

		JPanel jPanel = new JPanel();
		jPanel.setLayout(new GridBagLayout());
		GridBagConstraints ccc = new GridBagConstraints();
		ccc.anchor = GridBagConstraints.NORTH;
		ccc.gridx = 0;
		ccc.gridy = 0;
		jPanel.add(picPanel, ccc);
		ccc.gridx++;
		jPanel.add(DataPanel, ccc);

		ccc.gridx = 0;
		ccc.gridy++;
		ccc.gridwidth = 2;
		ccc.anchor = GridBagConstraints.CENTER;

		comContents = new JTextArea();
		comContents.setEditable(false);
		comContents.setText(NONE);
		JPanel p = new JPanel();
		p.add(comContents);
		p.setBorder(BorderFactory.createTitledBorder("COM"));

		jPanel.add(p, ccc);

		tabbedPane.add("Data", jPanel);

		securityInfo = new JTextArea();
		securityInfo.setEditable(false);
		securityInfo.setFont(new Font("Times New Roman", Font.BOLD, 14));

		tabbedPane.add("Security Info", securityInfo);

		add(tabbedPane, BorderLayout.CENTER);

		statusBar = new SecurityStatusBar();
		add(statusBar, BorderLayout.SOUTH);

		JMenuBar menu = new JMenuBar();
		JMenu fileMenu = new JMenu("File");
		saveSmartIDcard = new JMenuItem("Save as...");
		saveSmartIDcard.setActionCommand(SAVEID);
		saveSmartIDcard.addActionListener(this);
		saveSmartIDcard.setEnabled(false);
		fileMenu.add(saveSmartIDcard);
		savePicture = new JMenuItem("Save Picture...");
		savePicture.setActionCommand(SAVEPICTURE);
		savePicture.addActionListener(this);
		savePicture.setEnabled(false);
		fileMenu.add(savePicture);
		exitItem = new JMenuItem("Exit");
		exitItem.setActionCommand("exit");
		exitItem.addActionListener(this);
		fileMenu.add(exitItem);

		menu.add(fileMenu);

		JMenu viewMenu = new JMenu("View");
		viewDocCert = new JMenuItem("Doc. Certificate...");
		viewDocCert.setActionCommand(VIEWDOCCERT);
		viewDocCert.addActionListener(this);
		viewDocCert.setEnabled(false);
		viewMenu.add(viewDocCert);

		viewAAKey = new JMenuItem("AA pub. key...");
		viewAAKey.setActionCommand(VIEWAAKEY);
		viewAAKey.addActionListener(this);
		viewAAKey.setEnabled(false);
		viewMenu.add(viewAAKey);

		viewEACKeys = new JMenuItem("EAC card keys...");
		viewEACKeys.setActionCommand(VIEWEACKEYS);
		viewEACKeys.addActionListener(this);
		viewEACKeys.setEnabled(false);
		viewMenu.add(viewEACKeys);

		menu.add(viewMenu);

		JMenu helpMenu = new JMenu("Help");
		aboutItem = new JMenuItem("About");
		aboutItem.setActionCommand("about");
		aboutItem.addActionListener(this);
		helpMenu.add(aboutItem);

		menu.add(helpMenu);

		setJMenuBar(menu);

		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setLocation(500, 100);
		setSize(800, 700); // set frame size
		//setVisible(true);
		// The frame is initially invisible, pops up when a
		// valid passwd manager is found in the reader
	}

	// Handles input events
	public void actionPerformed(ActionEvent e) {
		if ("exit".equals(e.getActionCommand())) {
			System.exit(0);
		} else if ("about".equals(e.getActionCommand())) {
			JOptionPane.showMessageDialog(this, "SmartID card v1.0.\n By Qingbao Guo");
		} else if (SAVEPICTURE.equals(e.getActionCommand())) {
			byte[] data = ((PicturePane) picturesPane.getSelectedComponent())
					.getImage();
			if (data == null) {
				return;
			}
			File f = GUIutil.getFile(this, "Save file", true);
			if (f != null) {
				try {
					Files.writeFile(f, data);
				} catch (Exception ex) {
					ex.printStackTrace();
				}
			}
		} else if (SAVEID.equals(e.getActionCommand())) {
			JFileChooser fileChooser = new JFileChooser();
			fileChooser
					.setFileFilter(net.sourceforge.scuba.util.Files.ZIP_FILE_FILTER);
			int choice = fileChooser.showSaveDialog(getContentPane());
			switch (choice) {
				case JFileChooser.APPROVE_OPTION:
					try {
						File file = fileChooser.getSelectedFile();
						FileOutputStream fileOut = new FileOutputStream(file);
						ZipOutputStream zipOut = new ZipOutputStream(fileOut);
						for (short fid : smartID.getFileList()) {
							String entryName = Hex.shortToHexString(fid) + ".bin";
							InputStream dg = smartID.getInputStream(fid);
							zipOut.putNextEntry(new ZipEntry(entryName));
							int bytesRead;
							byte[] dgBytes = new byte[1024];
							while ((bytesRead = dg.read(dgBytes)) > 0) {
								zipOut.write(dgBytes, 0, bytesRead);
							}
							zipOut.closeEntry();
						}
						zipOut.finish();
						zipOut.close();
						fileOut.flush();
						fileOut.close();
						break;
					} catch (IOException fnfe) {
						fnfe.printStackTrace();
					}
				default:
					break;
			}
		} else if (VIEWDOCCERT.equals(e.getActionCommand())) {
			try {
				X509Certificate c = sodFile.getDocSigningCertificate();
				viewData(c.toString(), c.getEncoded());
			} catch (Exception ex) {
				ex.printStackTrace();
			}
		} else if (VIEWAAKEY.equals(e.getActionCommand())) {
			PublicKey k = dg15file.getPublicKey();
			viewData(k.toString(), k.getEncoded());
		} else if (VIEWEACKEYS.equals(e.getActionCommand())) {
			String s = "";
			int count = 0;
			Set<Integer> ids = dg14file.getIds();
			List<byte[]> keys = new ArrayList<byte[]>();
			for (Integer id : ids) {
				if (count != 0) {
					s += "\n";
				}
				if (id != -1) {
					s += "Key identifier: " + id + "\n";
				}
				PublicKey k = dg14file.getKey(id);
				s += k.toString();
				keys.add(k.getEncoded());
				count++;
			}
			viewData(s, keys);
		}
	}

	private void viewData(String s, byte[] data) {
		List<byte[]> l = new ArrayList<byte[]>();
		l.add(data);
		new ViewWindow(this, "View", s, l);
	}

	private void viewData(String s, List<byte[]> data) {
		new ViewWindow(this, "View", s, data);
	}

	private void addPicture(String title, byte[] image, String mimeType,
			String date) {

		PicturePane picture = new PicturePane(title, image, mimeType, date);
		picturesPane.addTab(picture.getTitle(), picture);
	}

	void readData() {
		List<Short> files = smartID.getFileList();
		InputStream in = null;
		Short fid = BasicService.EF_COM;
		files.remove(fid);
		try {
			fid = BasicService.EF_DG1;
			if (files.contains(fid)) {
				in = smartID.getInputStream(fid);
				dg1file = new DG_1_FILE(in);
				BasicInfo bi = dg1file.getInfo();
				DataPanel.setValue("sur", bi.sur);
				DataPanel.setValue("given", bi.given);
				DataPanel.setValue("gender", bi.gender);
				DataPanel.setValue("dob", bi.dob);
				DataPanel.setValue("pob", bi.pob);
				DataPanel.setValue("issue", bi.issue);
				DataPanel.setValue("expriy", bi.expriy);
				DataPanel.setValue("country", bi.country);
				DataPanel.setValue("authority", bi.authority);
				DataPanel.setValue("id", bi.id);
				files.remove(fid);
			}
			fid = BasicService.EF_DG2;
			if (files.contains(fid)) {
				in = smartID.getInputStream(fid);
				dg2file = new DG_2_FILE(in);
				addPicture("DG2", dg2file.getImage(), dg2file.getMimeType(),
						null);
				savePicture.setEnabled(true);
				files.remove(fid);
			}
			fid = BasicService.EF_DG3;
			if (files.contains(fid)) {
				in = smartID.getInputStream(fid);
				dg3file = new DG_3_FILE(in);
				DataPanel.setValue("emtry", dg3file.emtry);
				files.remove(fid);
			}
			fid = BasicService.EF_DG4;
			if (files.contains(fid)) {
				in = smartID.getInputStream(fid);
				dg4file = new DG_4_FILE(in);
				addPicture("DG4", dg4file.getImage(), dg4file.getMimeType(),
						null);
				files.remove(fid);
			}
			fid = BasicService.EF_DG15;
			if (files.contains(fid)) {
				in = smartID.getInputStream(fid);
				dg15file = new DG_15_FILE(in);
				viewAAKey.setEnabled(true);
				files.remove(fid);
			}
			fid = BasicService.EF_DG14;
			if (files.contains(fid)) {
				in = smartID.getInputStream(fid);
				dg14file = new DG_14_FILE(in);
				viewEACKeys.setEnabled(true);
				files.remove(fid);
			}
			fid = BasicService.EF_SOD;
			if (files.contains(fid)) {
				in = smartID.getInputStream(fid);
				sodFile = new DG_SOD(in);
				viewDocCert.setEnabled(true);
				securityInfo.append(sodFile.toString());
				files.remove(fid);
			}
			// See if there are any files that we did not know
			// how to handle:
			for (Short f : files) {
				System.out.println("Don't know how to handle file ID: "
						+ Hex.shortToHexString(f));
			}
			saveSmartIDcard.setEnabled(true);
		} catch (Exception ioe) {
			ioe.printStackTrace();
		}
	}

	// Check all kinds of security integrity things on the data read in
	void verifySecurity(BasicService service) {
		if (dg15file != null) {
			PublicKey k = dg15file.getPublicKey();
			try {
				boolean result = service.doAA(k);
				if (result) {
					statusBar.setAAOK();
				} else {
					statusBar.setAAFail("wrong signature");
				}
			} catch (CardServiceException cse) {
				statusBar.setAAFail(cse.getMessage());
			}
		} else {
			statusBar.setAANotChecked();
		}

		List<Integer> comDGList = new ArrayList<Integer>();
		for (Integer tag : comFile.getTagList()) {
			comDGList.add(FileStructure.lookupDataGroupNumberByTag(tag));
		}
		Collections.sort(comDGList);

		Map<Integer, byte[]> hashes = sodFile.getDataGroupHashes();

		List<Integer> tagsOfHashes = new ArrayList<Integer>();
		tagsOfHashes.addAll(hashes.keySet());
		Collections.sort(tagsOfHashes);
		if (!tagsOfHashes.equals(comDGList)) {
			statusBar.setPAFail("\"Sanity check\" failed!");
		} else {
			try {
				String digestAlgorithm = sodFile.getDigestAlgorithm();
				MessageDigest digest = MessageDigest
						.getInstance(digestAlgorithm);
				for (int dgNumber : hashes.keySet()) {
					short fid = FileStructure.lookupFIDByTag(FileStructure
							.lookupTagByDataGroupNumber(dgNumber));
					byte[] storedHash = hashes.get(dgNumber);

					digest.reset();

					InputStream dgIn = null;
					Exception exc = null;
					try {
						dgIn = smartID.getInputStream(fid);
					} catch (Exception ex) {
						exc = ex;
					}

					if (dgIn == null && smartID.hasEAC()
							&& !smartID.wasEACPerformed()
							&& smartID.getEACFiles().contains(fid)) {
						continue;
					} else {
						if (exc != null) {
							throw exc;
						}
					}

					byte[] buf = new byte[4096];
					while (true) {
						int bytesRead = dgIn.read(buf);
						if (bytesRead < 0) {
							break;
						}
						digest.update(buf, 0, bytesRead);
					}
					byte[] computedHash = digest.digest();
					if (!Arrays.equals(storedHash, computedHash)) {
						statusBar.setPAFail("Authentication of DG" + dgNumber
								+ " failed");

					}
					securityInfo.append("DG: " + dgNumber + " Computed hash: "
							+ Hex.bytesToHexString(computedHash) + " (match!)" + "\n");
				}
				statusBar.setPAOK("Hash alg. " + digestAlgorithm);
			} catch (Exception e) {
				statusBar.setPAFail(e.getMessage());
			}
		}
		try {
			X509Certificate docSigningCert = sodFile.getDocSigningCertificate();
			if (sodFile.checkDocSignature(docSigningCert)) {
				//statusBar.setDSOK("sig. alg. "
				//+ sodFile.getDigestEncryptionAlgorithm());
			} else {
				//statusBar.setDSFail("DS Signature incorrect");
			}
		} catch (Exception e) {
			e.printStackTrace();
			//statusBar.setDSFail(e.getMessage());
		}
	}

	// Make the COM file contents human readable
	private String formatComFile() {
		if (comFile == null) {
			return NONE;
		}
		List<Integer> list = comFile.getDGNumbers();
		String result = "Data groups:";
		for (Integer i : list) {
			result += " DG" + i.toString();
		}
		result += "\n";
		SecurityObjectIndicator[] sois = comFile.getSOIArray();
		if (sois.length > 0) {
			result += "Security Object Indicators:\n";
			for (SecurityObjectIndicator soi : sois) {
				result += "  " + soi.toString() + "\n";
			}
		}
		result = result.substring(0, result.length() - 1);
		return result;
	}

	public JTextArea getCOMContentsField() {
		return comContents;
	}

	public SecurityStatusBar getStatusBar() {
		return statusBar;
	}

	public SmartID getSmartID() {
		return smartID;
	}

	public void setSmartID(SmartID dl) {
		this.smartID = dl;
	}

	public DG_COM getCOMFile() {
		return comFile;
	}

	public void setCOMFile(DG_COM comFile) {
		this.comFile = comFile;
		comContents.setText(formatComFile());
	}

	public static void main(String[] args) {

		Reader rd = new Reader();
	}
}
