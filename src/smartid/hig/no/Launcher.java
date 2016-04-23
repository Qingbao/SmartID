/**
 *
 */
package smartid.hig.no;

import smartid.hig.no.gui.GUI;
import smartid.hig.no.gui.Writer;

/**
 * Runs the reader or the writer GUI
 *
 * @author Qingbao.Guo
 *
 */
public class Launcher {

	/**
	 * @param args indicate whether we should run the reader or the writer.
	 * Reader is the default
	 *
	 *
	 */
	public static void main(String[] args) {
		if (args.length == 1 && "writer".equals(args[0])) {
			Writer.main(new String[0]);
		} else {
			GUI.main(new String[0]);
		}

	}

}
