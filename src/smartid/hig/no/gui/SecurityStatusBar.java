package smartid.hig.no.gui;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JLabel;
import javax.swing.JPanel;

public class SecurityStatusBar extends JPanel {

	private JLabel bac;

	private JLabel eac;

	private JLabel aa;

	private JLabel pa;

	private JLabel ds;

	public SecurityStatusBar() {
		setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.insets = new Insets(2, 2, 2, 2);
		c.anchor = GridBagConstraints.WEST;
		c.gridx = 0;
		c.gridy = 0;
		JLabel l = new JLabel("BAC:");
		l.setToolTipText("Basic Acces Control");
		add(l, c);
		c.gridx++;
		bac = new JLabel("?");
		bac.setToolTipText("Not checked");
		add(bac, c);
		c.gridx++;

		l = new JLabel(" EAC:");
		l.setToolTipText("Extended Acces Control");
		add(l, c);
		c.gridx++;
		eac = new JLabel("?");
		eac.setToolTipText("Not checked");
		add(eac, c);
		c.gridx++;

		l = new JLabel(" AA:");
		l.setToolTipText("Active Authentication");
		add(l, c);
		c.gridx++;
		aa = new JLabel("?");
		aa.setToolTipText("Not checked");
		add(aa, c);
		c.gridx++;

		l = new JLabel(" PA:");
		l.setToolTipText("Passive Authentication");
		add(l, c);
		c.gridx++;
		pa = new JLabel("?");
		pa.setToolTipText("Not checked");
		add(pa, c);
		c.gridx++;

		/*l = new JLabel(" DS:");
		 l.setToolTipText("Document Signature");
		 add(l, c);
		 c.gridx++;
		 ds = new JLabel("?");
		 ds.setToolTipText("Not checked");
		 add(ds, c);
		 c.gridx++;*/
	}

	void setBACOK() {
		bac.setText("OK");
		bac.setForeground(Color.GREEN);
		bac.setToolTipText("Status OK");
	}

	void setBACFail(String reason) {
		bac.setText("FAIL");
		bac.setForeground(Color.RED);
		bac.setToolTipText("Status FAILED: " + reason);
	}

	void setBACNotChecked() {
		eac.setText("X");
		eac.setForeground(Color.BLACK);
		eac.setToolTipText("BAC not available");
	}

	void setEACOK() {
		eac.setText("OK");
		eac.setForeground(Color.GREEN);
		eac.setToolTipText("Status OK");
	}

	void setEACFail(String reason) {
		eac.setText("FAIL");
		eac.setForeground(Color.RED);
		eac.setToolTipText("Status FAILED: " + reason);
	}

	void setEACNotChecked() {
		eac.setText("X");
		eac.setForeground(Color.BLACK);
		eac.setToolTipText("EAC not available");
	}

	void setAAOK() {
		aa.setText("OK");
		aa.setForeground(Color.GREEN);
		aa.setToolTipText("Status OK");
	}

	void setAAFail(String reason) {
		aa.setText("FAIL");
		aa.setForeground(Color.RED);
		aa.setToolTipText("Status FAILED: " + reason);
	}

	void setAANotChecked() {
		aa.setText("X");
		aa.setForeground(Color.BLACK);
		aa.setToolTipText("AA not available");
	}

	void setPAOK() {
		pa.setText("OK");
		pa.setForeground(Color.GREEN);
		pa.setToolTipText("Status OK");
	}

	void setPAOK(String info) {
		pa.setText("OK");
		pa.setForeground(Color.GREEN);
		pa.setToolTipText("Status OK: " + info);
	}

	void setPAFail(String reason) {
		pa.setText("FAIL");
		pa.setForeground(Color.RED);
		pa.setToolTipText("Status FAILED: " + reason);
	}

	void setDSOK() {
		ds.setText("OK");
		ds.setForeground(Color.GREEN);
		ds.setToolTipText("Status OK");
	}

	void setDSOK(String info) {
		ds.setText("OK");
		ds.setForeground(Color.GREEN);
		ds.setToolTipText("Status OK: " + info);
	}

	void setDSFail(String reason) {
		ds.setText("FAIL");
		ds.setForeground(Color.RED);
		ds.setToolTipText("Status FAILED: " + reason);
	}

}
