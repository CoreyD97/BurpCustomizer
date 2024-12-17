package com.coreyd97.burpcustomizer;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import lombok.SneakyThrows;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import java.awt.*;

public class PreviewPanel extends JPanel {

    PreviewPanel() {
        this.setLayout(new BorderLayout());
        this.setBorder(BorderFactory.createLineBorder(Color.BLACK, 1));
        try {
//            setTheme(UIManager.getLookAndFeel());
            JComponent previewContent = buildPreviewContent();
            this.add(previewContent, BorderLayout.CENTER);
        } catch (Exception e) {
            reset();
        }
    }

    public void reset() {
        this.removeAll();
        JLabel noSelected = new JLabel("No theme selected.");
        noSelected.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        noSelected.setHorizontalAlignment(JLabel.CENTER);
        this.add(noSelected, BorderLayout.CENTER);
        this.revalidate();
        this.repaint();
    }


    public void setPreviewTheme(LookAndFeel lookAndFeel) throws UnsupportedLookAndFeelException {
        this.removeAll();
        //Disabled due to deadlock issues with lazy loading.
//        LookAndFeel oldLaf = UIManager.getLookAndFeel();
//        this.removeAll();
//        JComponent previewContent = buildPreviewContent();
//        this.add(previewContent, BorderLayout.CENTER);
//        UIManager.setLookAndFeel(oldLaf);
//        this.revalidate();
//        this.repaint();
    }

    public JComponent buildPreviewContent() {
        JLabel jLabelEnabled = new JLabel("Enabled");
        JLabel jLabelDisabled = new JLabel("Disabled");
        jLabelDisabled.setEnabled(false);

        JButton jbuttonEnabled = new JButton("Enabled");
        JButton jbuttonDisabled = new JButton("Disabled");
        jbuttonDisabled.setEnabled(false);

        JCheckBox JCheckBoxEnabled = new JCheckBox("Enabled");
        JCheckBox JCheckBoxDisabled = new JCheckBox("Disabled");
        JCheckBox JCheckBoxEnabledSelected = new JCheckBox("Selected");
        JCheckBox JCheckBoxDisabledSelected = new JCheckBox("Selected disabled");
        JCheckBoxDisabled.setEnabled(false);
        JCheckBoxDisabledSelected.setEnabled(false);
        JCheckBoxEnabledSelected.setSelected(true);
        JCheckBoxDisabledSelected.setSelected(true);

        JRadioButton JRadioButtonEnabled = new JRadioButton("Enabled");
        JRadioButton JRadioButtonDisabled = new JRadioButton("Disabled");
        JRadioButton JRadioButtonEnabledSelected = new JRadioButton("Selected");
        JRadioButton JRadioButtonDisabledSelected = new JRadioButton("Selected disabled");
        JRadioButtonDisabled.setEnabled(false);
        JRadioButtonDisabledSelected.setEnabled(false);
        JRadioButtonEnabledSelected.setSelected(true);
        JRadioButtonDisabledSelected.setSelected(true);

        JComboBox<String> JComboBoxEnabled = new JComboBox<>(new String[]{"Editable", "Item A", "Item B"});
        JComboBox<String> JComboBoxDisabled = new JComboBox<>(new String[]{"Disabled"});
        JComboBox<String> JComboBoxEnabledNotEditable = new JComboBox<>(new String[]{"Not Editable", "Item A", "Item B"});
        JComboBox<String> JComboBoxDisabledNotEditable = new JComboBox<>(new String[]{"Not Editable Disabled"});
        JComboBoxDisabled.setEnabled(false);
        JComboBoxDisabledNotEditable.setEnabled(false);
        JComboBoxDisabledNotEditable.setEditable(false);
        JComboBoxEnabledNotEditable.setEditable(false);

        JSpinner JSpinnerEnabled = new JSpinner();
        JSpinner JSpinnerDisabled = new JSpinner();
        JSpinnerDisabled.setEnabled(false);

        JTextField JTextFieldEnabled = new JTextField("Editable");
        JTextField JTextFieldDisabled = new JTextField("Disabled");
        JTextField JTextFieldEnabledNotEditable = new JTextField("Not Editable");
        JTextField JTextFieldDisabledNotEditable = new JTextField("Not Editable Disabled");
        JTextFieldDisabled.setEnabled(false);
        JTextFieldDisabledNotEditable.setEnabled(false);
        JTextFieldDisabledNotEditable.setEditable(false);
        JTextFieldEnabledNotEditable.setEditable(false);

        JPasswordField JPasswordFieldEnabled = new JPasswordField("Editable");
        JPasswordField JPasswordFieldDisabled = new JPasswordField("Disabled");
        JPasswordField JPasswordFieldEnabledNotEditable = new JPasswordField("Not Editable");
        JPasswordField JPasswordFieldDisabledNotEditable = new JPasswordField("Not Editable Disabled");
        JPasswordFieldDisabled.setEnabled(false);
        JPasswordFieldDisabledNotEditable.setEnabled(false);
        JPasswordFieldDisabledNotEditable.setEditable(false);
        JPasswordFieldEnabledNotEditable.setEditable(false);

        PanelBuilder panelBuilder = new PanelBuilder();
        panelBuilder.setComponentGrid(new Component[][]{
                new Component[]{new JLabel("JLabel:"), jLabelEnabled, jLabelDisabled, null, null},
                new Component[]{new JLabel("JButton:"), jbuttonEnabled, jbuttonDisabled, null, null},
                new Component[]{new JLabel("JCheckBox:"), JCheckBoxEnabled, JCheckBoxDisabled, JCheckBoxEnabledSelected, JCheckBoxDisabledSelected},
                new Component[]{new JLabel("JRadioButton:"), JRadioButtonEnabled, JRadioButtonDisabled, JRadioButtonEnabledSelected, JRadioButtonDisabledSelected},
                new Component[]{new JLabel("JComboBox:"), JComboBoxEnabled, JComboBoxDisabled, JComboBoxEnabledNotEditable, JComboBoxDisabledNotEditable},
                new Component[]{new JLabel("JSpinner:"), JSpinnerEnabled, JSpinnerDisabled, null, null},
                new Component[]{new JLabel("JTextField:"), JTextFieldEnabled, JTextFieldDisabled, JTextFieldEnabledNotEditable, JTextFieldDisabledNotEditable},
                new Component[]{new JLabel("JPasswordField:"), JPasswordFieldEnabled, JPasswordFieldDisabled, JPasswordFieldEnabledNotEditable, JPasswordFieldDisabledNotEditable},
        });
        panelBuilder.setAlignment(Alignment.FILL);
        JPanel basicComponents = panelBuilder.build();
        basicComponents.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JTextArea jTextArea = new JTextArea("An editable text area");
        jTextArea.setWrapStyleWord(true);
        JScrollPane jScrollPane = new JScrollPane(jTextArea);
        jScrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        JTable jTable = new JTable(new Object[][]{new Object[]{false, "A", "1", "?"}, new Object[]{true, "B", "2", "!"}}, new String[]{"Boolean", "Letters", "Numbers", "Symbols"});
        DefaultMutableTreeNode treeNode = new DefaultMutableTreeNode("Items");
        treeNode.add(new DefaultMutableTreeNode("Item A"));
        treeNode.add(new DefaultMutableTreeNode("Item B"));
        DefaultMutableTreeNode childNode = new DefaultMutableTreeNode("Item C");
        childNode.add(new DefaultMutableTreeNode("C - 1"));
        childNode.add(new DefaultMutableTreeNode("C - 2"));
        childNode.add(new DefaultMutableTreeNode("C - 3"));
        treeNode.add(childNode);

        JTree jTree = new JTree(treeNode);
        JList<String> jList = new JList<>(new String[]{"Item A", "Item B", "Item C", "Item D", "Item E", "Item F"});

        panelBuilder = new PanelBuilder();
        panelBuilder.setComponentGrid(new Component[][]{
                new Component[]{new JLabel("JEditor"), null},
                new Component[]{jScrollPane, jScrollPane},
                new Component[]{jScrollPane, jScrollPane},
                new Component[]{new JLabel("JTable"), null},
                new Component[]{jTable, jTable},
                new Component[]{new JLabel("JTree"), new JLabel("JList")},
                new Component[]{new JScrollPane(jTree), new JScrollPane(jList)},
        });
        int[][] weights = new int[][]{
                new int[]{0, 0},
                new int[]{1, 1},
                new int[]{1, 1},
                new int[]{0, 0},
                new int[]{1, 1},
                new int[]{0, 0},
                new int[]{5, 5},
        };
        panelBuilder.setGridWeightsX(weights);
        panelBuilder.setGridWeightsY(weights);
        panelBuilder.setAlignment(Alignment.FILL);
        JPanel otherComponents = panelBuilder.build();

        JTabbedPane jTabbedPane = new JTabbedPane();
        jTabbedPane.add("Basic", basicComponents);
        jTabbedPane.add("Data", otherComponents);

        JPanel jPanel = new JPanel(new BorderLayout());
        jPanel.add(jTabbedPane, BorderLayout.CENTER);
        return jPanel;
    }

}
