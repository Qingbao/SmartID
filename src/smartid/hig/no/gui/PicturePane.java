package smartid.hig.no.gui;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Image;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;

import eu.medsea.mimeutil.MimeType;
import eu.medsea.mimeutil.MimeUtil;

import net.sourceforge.scuba.util.Files;

/**
 * A simple panel for displaying a picture (photo or signature) and some simple
 * information (tag). The picture can be loaded from a file.
 *
 *
 */
public class PicturePane extends JPanel implements ActionListener {

	private JLabel picture = null;

	private JTextArea info = null;

	private byte[] image = null;

	private String mimeType = null;

	private String date = null;

	private String title = null;

	private static final String loadCommand = "load";

	/**
	 * Constructs a default picture panel.
	 *
	 * @param title the display title of the panel
	 * @param editable when true, the picture can be loaded from a file
	 */
	public PicturePane(String title, boolean editable) {
		this.title = title;
		setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.anchor = GridBagConstraints.WEST;

		c.gridx = 0;
		c.gridy = 0;
		c.insets = new Insets(5, 5, 5, 5);

		picture = new JLabel("No picture");
		picture.setSize(100, 200);
		add(picture, c);
		c.gridy = 1;
		info = new JTextArea(2, 10);
		info.setEditable(false);
		info.setText("No info.\n");
		add(info, c);

		if (editable) {
			c.gridx = 0;
			c.gridy = 2;
			JButton loadButton = new JButton("Load...");
			loadButton.setActionCommand(loadCommand);
			loadButton.addActionListener(this);
			add(loadButton, c);
		}

	}

	/**
	 * Constructs uneditable picture panel with a predefined picture, mimeType
	 * and date info.
	 *
	 * @param title the display title of the panel
	 * @param image raw image data (.jpg file contents)
	 * @param mimeType string containing the mime type of the raw image data
	 * @param date string with the picture date stamp
	 */
	public PicturePane(String title, byte[] image, String mimeType, String date) {
		this(title, image, mimeType, date, false);
	}

	/**
	 * See above, editable version.
	 */
	public PicturePane(String title, byte[] image, String mimeType, String date, boolean editable) {
		this(title, editable);
		this.image = image;
		this.mimeType = mimeType;
		this.date = date;
		updatePicture();
	}

	// Repaints the picture
	private void updatePicture() {

		BufferedImage bufferedImage = null;
		try {
			Iterator<ImageReader> readers = ImageIO
					.getImageReadersByMIMEType(mimeType);
			ImageInputStream iis = ImageIO
					.createImageInputStream(new ByteArrayInputStream(image));
			if (readers.hasNext()) {
				ImageReader reader = readers.next();
				reader.setInput(iis);
				bufferedImage = reader.read(0);
			}
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		picture.setText("");
		if (bufferedImage != null) {
			picture.setIcon(new ImageIcon(bufferedImage.getScaledInstance(200, -1, Image.SCALE_SMOOTH)));
		}
		if (mimeType != null) {
			info.setText("MIME type: " + mimeType + "\n" + (date == null ? "" : "Date: " + date));
		}
		repaint();
		revalidate();
	}

	/**
	 * Handles input events.
	 */
	public void actionPerformed(ActionEvent e) {
		if (loadCommand.equals(e.getActionCommand())) {
			JFileChooser fileChooser = new JFileChooser();
			fileChooser.setFileFilter(Files.IMAGE_FILE_FILTER);
			int choice = fileChooser.showOpenDialog(this);
			switch (choice) {
				case JFileChooser.APPROVE_OPTION:
					try {
						File file = fileChooser.getSelectedFile();
						// FIXME: not sure if this will work for JPEG2000 files
						String mimeType = ((MimeType) (MimeUtil.getMimeTypes(file).iterator().next())).toString();
						byte[] contents = smartid.hig.no.utils.Files
								.loadFile(file);
						Date d = new Date(System.currentTimeMillis());
						image = contents;
						this.mimeType = mimeType;
						this.date = new SimpleDateFormat("yyyyMMddHHmmss").format(d);
						updatePicture();
					} catch (Exception ex) {
						ex.printStackTrace();
					}

			}
		}
	}

	/**
	 * Returns the raw image data.
	 *
	 * @return the raw image data
	 */
	public byte[] getImage() {
		return image;
	}

	/**
	 * Returns the mime type string of the displayed picture raw data.
	 *
	 * @return the mime type string of the displayed picture raw data
	 */
	public String getMimeType() {
		return mimeType;
	}

	/**
	 * Returns the string with the date stamp.
	 *
	 * @return the string with the date stamp
	 */
	public String getDate() {
		return date;
	}

	/**
	 * Returns the display title.
	 *
	 * @return the display title
	 */
	public String getTitle() {
		return title;
	}

}
