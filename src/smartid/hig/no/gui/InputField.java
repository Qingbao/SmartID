
package smartid.hig.no.gui;

/**
 * Stores format information for a single field. Each input specification is
 * identified with a name, has a display label, and belongs to one of the data
 * groups.
 * 
 * 
 */
public class InputField {

    String id;

    String label;

    FieldFormat format;

    FieldGroup group;

    /**
     * Constructor.
     * 
     * @param id
     *            identifier string for the input specification
     * @param label
     *            display lable
     * @param format
     *            the format for the field
     * @param group
     *            the group the field should belong to
     */
    public InputField(String id, String label, FieldFormat format,
            FieldGroup group) {
        this.id = id;
        this.label = label;
        this.format = format;
        this.group = group;
    }

    /**
     * Checks object equality. (Used when storing this object in hash maps and
     * such).
     */
    public boolean equals(Object o) {
        if (!(o instanceof InputField)) {
            return false;
        }
        return ((InputField) o).id.equals(id);
    }

}
