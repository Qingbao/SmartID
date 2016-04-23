package smartid.hig.no.gui;

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import net.sourceforge.scuba.util.Hex;
import smartid.hig.no.utils.Files;
import smartid.hig.no.utils.GUIutil;

/**
 * A simple view window to display data in two formats: performatted and raw
 * (hex). Enables saving of files (only the raw contents).
 *
 *
 */
public class ViewWindow extends JDialog implements ActionListener {

	private JTextArea ta = null;

	private List<byte[]> rawContents = null;

	private String contents = null;

	boolean viewRaw = false;

	/**
	 * Constructor.
	 *
	 * @param parent the parent for this dialog
	 * @param title the title for this dialog
	 * @param contents the string with the performatted contents
	 * @param rawContents the raw contents ("saveable" contents)
	 */
	public ViewWindow(JFrame parent, String title, String contents,
			List<byte[]> rawContents) {
		super();
		setTitle(title);
		setLayout(new GridBagLayout());
		this.rawContents = rawContents;
		this.contents = contents;

		GridBagConstraints c = new GridBagConstraints();

		ta = new JTextArea(contents);
		ta.setEditable(false);

		JScrollPane sp = new JScrollPane(ta,
				JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
				JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);

		sp.setMinimumSize(new Dimension(400, 300));
		c.gridx = 0;
		c.gridwidth = 3;
		c.gridy = 0;
		c.fill = GridBagConstraints.BOTH;
		add(sp, c);

		c.gridwidth = 1;
		c.gridy++;
		c.fill = GridBagConstraints.NONE;
		c.anchor = GridBagConstraints.WEST;
		c.insets = new Insets(5, 0, 5, 20);

		JButton button = new JButton("Save...");
		button.setActionCommand("save");
		button.addActionListener(this);
		add(button, c);

		c.gridx++;

		button = new JButton("Toggle View");
		button.setActionCommand("toggle");
		button.addActionListener(this);
		button.setEnabled(rawContents != null);
		add(button, c);

		c.gridx++;

		button = new JButton("Close");
		button.setActionCommand("close");
		button.addActionListener(this);
		add(button, c);

		setSize(new Dimension(420, 400));
		setResizable(false);
		setLocationRelativeTo(parent);
		setVisible(true);
	}

	/**
	 * Handles input events.
	 */
	public void actionPerformed(ActionEvent e) {
		if (e.getActionCommand().equals("save")) {
			if (rawContents != null && rawContents.size() > 0) {
				for (int i = 0; i < rawContents.size(); i++) {
					String num = rawContents.size() != 1 ? "" + (i + 1) : "";
					File f = GUIutil.getFile(this, "Save File " + num, true);
					if (f != null) {
						try {
							Files.writeFile(f, rawContents.get(i));
						} catch (Exception ex) {
							ex.printStackTrace();
						}

					}
				}
			}

		}
		if (e.getActionCommand().equals("toggle")) {
			viewRaw = !viewRaw;
			if (viewRaw) {
				String all = "";
				for (byte[] r : rawContents) {
					all += "\n" + Hex.bytesToHexString(r, 20);
				}
				ta.setText(all.substring(1));
			} else {
				ta.setText(contents);
			}
		}
		if (e.getActionCommand().equals("close")) {
			dispose();
		}

	}

}
