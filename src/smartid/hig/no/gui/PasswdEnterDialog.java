
package smartid.hig.no.gui;

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JTextField;
import javax.swing.filechooser.FileFilter;

import smartid.hig.no.certificates.TerminalCVCertificateDirectory;

/**
 * A simple dialog for entering the BAC string, i.e. user passpword.
 * 
 * 
 */
public class PasswdEnterDialog extends JDialog implements ActionListener {

    private JTextField bacString = null;

    private byte[] bacValue = null;
    
    private JCheckBox sha1 = null;

    public PasswdEnterDialog(JFrame parent, String title) {
        super(parent);
        setTitle(title);
        setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(5, 5, 5, 5);

        c.gridx = 0;
        c.gridy=0;
        c.anchor = GridBagConstraints.WEST;
        add(new JLabel("Enter Password:"), c);

        c.gridx++;
        sha1 = new JCheckBox(" SHA1", true);
        add(sha1, c);
        
        bacString = new JTextField(20);
        bacString.addActionListener(this);

        c.gridx = 0;
        c.gridwidth = 2;
        c.gridy++;
        c.fill = GridBagConstraints.BOTH;
        c.anchor = GridBagConstraints.CENTER;
        add(bacString, c);

        c.gridwidth = 1;
        c.gridy++;
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.CENTER;
        c.insets = new Insets(5, 0, 5, 20);

        JButton button = new JButton("OK");
        button.setActionCommand("ok");
        button.setMnemonic('O');
        button.setDefaultCapable(true);
        button.addActionListener(this);
        add(button, c);

        c.gridx++;

        button = new JButton("Cancel");
        button.setActionCommand("cancel");
        button.setMnemonic('C');
        button.addActionListener(this);
        add(button, c);

        JMenuBar menu = new JMenuBar();
        JMenu fileMenu = new JMenu("File");
        JMenuItem load = new JMenuItem("Load Terminals...");
        load.setActionCommand("load");
        load.addActionListener(this);
        load.setEnabled(true);
        fileMenu.add(load);
        menu.add(fileMenu);
        setJMenuBar(menu);
        
        
        setSize(new Dimension(200, 150));
        setResizable(false);
        setModal(true);
        setLocationRelativeTo(getParent());
        setVisible(true);
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getActionCommand().equals("ok") || e.getSource() == bacString) {
            if(!sha1.isSelected()) {
              if(bacString.getText().length() == 0) {
                  bacValue = null;
              }else{
                  bacValue = bacString.getText().getBytes();
              }
            }else{
              try {
                MessageDigest md = MessageDigest.getInstance("SHA1");
                byte[] t = md.digest(bacString.getText().getBytes());
                bacValue = new byte[16];
                System.arraycopy(t, 0, bacValue, 0, 16);
              }catch(NoSuchAlgorithmException nsae) {
              }
            }
            dispose();
        }
        if (e.getActionCommand().equals("cancel")) {
            bacValue = null;
            dispose();
        }
        if (e.getActionCommand().equals("load")) {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setAcceptAllFileFilterUsed(false);
            fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            fileChooser.setFileFilter(new FileFilter() {
                public boolean accept(File f) { return f.isDirectory(); }
                public String getDescription() { return "Directories"; }               
            });
            int choice = fileChooser.showOpenDialog(this);
            switch (choice) {
            case JFileChooser.APPROVE_OPTION:
                try {
                    File file = fileChooser.getSelectedFile();
                    TerminalCVCertificateDirectory.getInstance().scanDirectory(file);
                } catch (IOException ioe) {
                    /* NOTE: Do nothing. */
                    // ioe.printStackTrace();
                }
                break;
            default: break;
            }

        }

    }

    public byte[] getBACString() {
        return bacValue;
    }

}
