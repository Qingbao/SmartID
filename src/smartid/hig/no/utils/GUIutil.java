
package smartid.hig.no.utils;

import java.awt.Component;
import java.io.File;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

/**
 * GUI utilities.
 * 
 * 
 */
public class GUIutil {

    /**
     * Shows a dialog to open/save file (the write parameter steers this). For
     * opening the file, the existence of the file is checked. For saving the
     * file an overwrite confirmation message is displayed if necessary.
     * 
     * @param parent
     *            the parent for the open/save dialog
     * @param title
     *            the dialog title
     * @param write
     *            if true the dialog is for saving the file, for opening
     *            otherwise
     * @return the chosen file as a {@link File} object, null if not existing or
     *         not overwritable
     */
    public static File getFile(Component parent, String title, boolean write) {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle(title);
        if (write) {
            fc.showSaveDialog(parent);
        } else {
            fc.showOpenDialog(parent);
        }
        File f = fc.getSelectedFile();
        if (f == null || (!write && !f.exists()) || (f.exists() && !f.isFile()))
            return null;
        if (write && f.exists()) {
            int r = JOptionPane.showConfirmDialog(parent, "File \""
                    + f.getName() + "\" exists. Overwrite?");
            if (r != 0)
                return null;
        }
        return f;
    }

}
