
package smartid.hig.no.gui;

/**
 * Tagging class to divide input fields into different data groups. Predefines
 * two groups: DG1, DG3.
 * 
 * 
 */
public class FieldGroup {

    public static final FieldGroup Data = new FieldGroup(
            "DG1");

    public static final FieldGroup extraData = new FieldGroup(
            "DG3", true);

    String name = null;

    boolean optional = false;

    /**
     * Constructor.
     * 
     * @param name
     *            display name of the group
     */
    FieldGroup(String name) {
        this(name, false);
    }

    /**
     * Constructor.
     * 
     * @param name
     *            display name of the group
     * @param optional
     *            whether the data group is optional
     */
    FieldGroup(String name, boolean optional) {
        this.name = name;
        this.optional = optional;
    }

}
