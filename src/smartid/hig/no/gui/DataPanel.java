
package smartid.hig.no.gui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.Iterator;
import java.util.Vector;

import javax.swing.InputVerifier;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;


/**
 * A panel to enter and display data (DG1, DG3) in an organised
 * fashion.
 * 
 * 
 */
public class DataPanel extends JPanel {

    Map<String, JTextField> textFields = new TreeMap<String, JTextField>();

    Map<String, InputField> fields = new TreeMap<String, InputField>();
    
    Map<String,JCheckBox> optDataGroupsIds = new TreeMap<String,JCheckBox>();
    private boolean editable;

    /**
     * 
     * @param fields
     *            an array of filed specifications
     * @param editable
     *            whether the fields should be editable by the user
     */
    public DataPanel(Frame frame, InputField[] fields, boolean editable) {
        
        Vector<FieldGroup> groups = new Vector<FieldGroup>();
        for (InputField f : fields) {
            if (!groups.contains(f.group))
                groups.add(f.group);
        }
        JTabbedPane pane = new JTabbedPane();
        Iterator<FieldGroup> it = groups.iterator();
        while (it.hasNext()) {
            FieldGroup g = it.next();
            final JPanel p = new JPanel();
            p.setLayout(new GridBagLayout());
            GridBagConstraints c = new GridBagConstraints();

            c.gridy = 0;
            c.insets = new Insets(5, 5, 5, 5);

            if (g.optional && editable) {
                JCheckBox box = new JCheckBox("Enable", false);
                box.addChangeListener((ChangeListener)frame);
                optDataGroupsIds.put(g.name, box);
                box.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        JCheckBox b = (JCheckBox) e.getSource();
                        boolean active = b.isSelected();
                        for (Component c : p.getComponents()) {
                            if (c == b)
                                continue;
                            c.setEnabled(active);
                        }
                    }
                });
                c.gridx = 1;
                p.add(box, c);
            }

            c.gridx = 0;
            c.gridy++;

            for (final InputField f : fields) {
                this.fields.put(f.id, f);
                if (f.group != g)
                    continue;
                JLabel l = new JLabel(f.label + "  ");
                l.setEnabled(!g.optional || !editable);
                c.anchor = GridBagConstraints.EAST;
                p.add(l, c);
                c.gridx++;
                c.anchor = GridBagConstraints.WEST;
                
                  final JTextField t = new JTextField(f.format.maxLength > 8 ? 10 : f.format.maxLength + 2);
                  t.setEnabled(!g.optional || !editable);
                  t.setEditable(editable);
                  t.setToolTipText(f.format.getHelpText());
                  t.setInputVerifier(new InputVerifier() {
                      @Override
                      public boolean verify(JComponent input) {
                          return f.format.isCorrectInput(((JTextField) input)
                                  .getText());
                      }
                  });
                  t.getCaret().addChangeListener(new ChangeListener() {
                      public void stateChanged(ChangeEvent e) {
                          if (t.getInputVerifier().verify(t)) {
                              t.setForeground(Color.BLACK);
                          } else {
                              t.setForeground(Color.RED);
                          }
                      }
                  });
                  p.add(t, c);
                  textFields.put(f.id, t);
                
                c.gridx = 0;
                c.gridy++;
            }
            pane.add(g.name, p);
        }
        this.add(pane);
        this.editable = editable;
    }

    /**
     * Returns a value form a given id as a string.
     * 
     * @param id
     *            the id of the field
     * @return the corresponding value
     */
    public String getValue(String id) {
        if (!textFields.get(id).isEnabled())
            return null;
        return textFields.get(id).getText();
    }

  
    
    
    /**
     * Sets a value for a given id
     * 
     * @param id
     *            the id of the field
     * @param value
     *            the value
     */
    public void setValue(String id, String value) {
        if(value == null) {
            JTextField tf = textFields.get(id); 
            tf.setText("");
            JPanel p = (JPanel)tf.getParent();
            for(Component c : p.getComponents()){
                if(c instanceof JCheckBox) {
                    if(!((JCheckBox)c).isSelected()) {
                        return;
                    }else{
                      ((JCheckBox)c).setSelected(false);
                    }
                }else{
                    c.setEnabled(false);
                }
            }
            return;
        }
        InputField f = fields.get(id);
        if (!value.equals("") && !f.format.isCorrectInput(value)
                && f.format.characters == FieldFormat.DIGITS
                && f.format.minLength == f.format.maxLength) {
            int c = f.format.maxLength - value.length();
            for (int i = 0; i < c; i++) {
                value = "0" + value;
            }
        }
        JTextField tf = textFields.get(id); 
        tf.setText(value);
        if (!editable) {
            tf.setToolTipText(value);
        }else if(!tf.isEnabled()){
            JPanel p = (JPanel)tf.getParent();
            for(Component c : p.getComponents()){
                c.setEnabled(true);
                if(c instanceof JCheckBox) {
                    ((JCheckBox)c).setSelected(true);
                }
            }
        }
    }

    /** 
     * 
     * @return the map of optional group check boxes.
     * This is needed in the parant frame.
     */
    public Map<String,JCheckBox> getOptionalDataGroupIds() {
        return optDataGroupsIds;
    }
    
}
