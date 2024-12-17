package com.coreyd97.burpcustomizer;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.formdev.flatlaf.FlatLaf;
import lombok.SneakyThrows;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.ItemEvent;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class CustomizerPanel extends JPanel {

    private final BurpCustomizer customizer;
    JButton viewOnGithubButton;
    private File selectedThemeFile;
    public final PreviewPanel previewPanel;
    private final JComboBox<UIManager.LookAndFeelInfo> lookAndFeelSelector;

    public CustomizerPanel(BurpCustomizer customizer){
        this.customizer = customizer;
        this.setLayout(new BorderLayout());

        JLabel headerLabel = new JLabel("Burp Customizer");
        Font font = this.getFont().deriveFont(32f).deriveFont(this.getFont().getStyle() | Font.BOLD);
        headerLabel.setFont(font);
        headerLabel.setHorizontalAlignment(SwingConstants.CENTER);

        JLabel subtitle = new JLabel("Because just a dark theme wasn't enough!");
        Font subtitleFont = subtitle.getFont().deriveFont(16f).deriveFont(subtitle.getFont().getStyle() | Font.ITALIC);
        subtitle.setFont(subtitleFont);
        subtitle.setHorizontalAlignment(SwingConstants.CENTER);

        subtitle.setBorder(new EmptyBorder(0, 0, 10, 0));

        JSeparator separator = new JSeparator(SwingConstants.HORIZONTAL);

        JPanel contactPanel = new JPanel(new GridLayout(2,0));
        contactPanel.setBorder(new EmptyBorder(10, 0, 0, 0));

        ImageIcon twitterImage = loadImage("TwitterLogo.png", 30, 30);
        JButton twitterButton;
        if(twitterImage != null){
            twitterButton = new JButton("Follow me on Twitter", twitterImage);
            twitterButton.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
            twitterButton.setIconTextGap(7);
        }else{
            twitterButton = new JButton("Follow me on Twitter");
        }

        twitterButton.addActionListener(actionEvent -> {
            try {
                Desktop.getDesktop().browse(new URI("https://twitter.com/coreyd97"));
            } catch (IOException | URISyntaxException e) {}
        });

        ImageIcon githubImage = getGithubIcon();
        if(githubImage != null){
            viewOnGithubButton = new JButton("View Project on GitHub", githubImage);
            viewOnGithubButton.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
            viewOnGithubButton.setIconTextGap(7);
        }else{
            viewOnGithubButton = new JButton("View Project on GitHub");
        }
        viewOnGithubButton.addActionListener(actionEvent -> {
            try {
                Desktop.getDesktop().browse(new URI("https://github.com/CoreyD97/BurpCustomizer"));
            } catch (IOException | URISyntaxException e) {}
        });
        contactPanel.add(new JLabel("Created by:"));
        contactPanel.add(twitterButton);
        contactPanel.add(new JLabel("Corey Arthur (@CoreyD97)"));
        contactPanel.add(viewOnGithubButton);
        contactPanel.setBorder(BorderFactory.createEmptyBorder(15,0,15,0));


        WrappedTextPane aboutContent = new WrappedTextPane();
        aboutContent.setEditable(false);
        aboutContent.setOpaque(false);
        aboutContent.setCaret(new NoTextSelectionCaret(aboutContent));
        JScrollPane aboutScrollPane = new JScrollPane(aboutContent);
        aboutScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        aboutScrollPane.setBorder(null);
        Style bold = aboutContent.getStyledDocument().addStyle("bold", null);
        StyleConstants.setBold(bold, true);
        Style italics = aboutContent.getStyledDocument().addStyle("italics", null);
        StyleConstants.setItalic(italics, true);


        String intro = "Everybody knows hackers only work at night, so for years people asked PortSwigger to implement a dark theme.\n" +
                "When they did, hackers rejoiced everywhere! But, some still wanted more... Until... Burp Customizer!\n\n" +
                "Burp Suite 2020.12 replaced the old Look and Feel classes with FlatLaf, an open source Look and Feel class " +
                "which also supports 3rd party themes developed for the IntelliJ Platform. This extension allows you to use " +
                "these themes in Burp Suite, and includes a number of bundled themes to try.\n\n";
        String notesHeader = "Notes:\n";
        String notes = "When switching from a dark -> light theme, or vice-versa, first change Burp's theme in \"User options -> Display\" or icons will not be colored correctly.";
        String limitationsHeader = "Limitations:\n";
        String limitations = "Since Burp uses a number of custom GUI elements, PortSwigger extended the default " +
                "Look and Feel classes with a number of additional properties. In order to try to make these blend in, I've " +
                "tried to find standard elements who's colors can be used to replace the custom properties. Some themes might " +
                "not have these properties, or might not fit the theme perfectly. If there are any elements which don't fit, " +
                "please submit an issue on GitHub including the theme name, and a screenshot.\n\n";
        String creditsHeader = "Credits:\n";
        String credits = "FlatLaf - https://www.formdev.com/flatlaf/\n" +
                                "All theme credits go to their original authors.";

        //Doing this an odd way since insertString seems to cause errors on windows!
        int offset = 0;
        String[] sections = new String[]{intro, limitationsHeader, limitations, creditsHeader, credits};
        Style[] styles = new Style[]{italics, bold, null, bold, null, bold, null, bold,
                null, bold, null, null, italics, null, italics, bold, null, italics, null};
        String content = String.join("", sections);
        aboutContent.setText(content);
        for (int i = 0; i < sections.length; i++) {
            String section = sections[i];
            if(styles[i] != null)
                aboutContent.getStyledDocument().setCharacterAttributes(offset, section.length(), styles[i], false);
            offset+=section.length();
        }

        aboutContent.setBorder(new EmptyBorder(0, 0, 20, 0));

        previewPanel = new PreviewPanel();
        previewPanel.setBorder(new EmptyBorder(10, 0, 10, 0));

        JLabel themeLabel = new JLabel("Select Theme");
        themeLabel.setFont(themeLabel.getFont().deriveFont(Font.BOLD));

        lookAndFeelSelector = new JComboBox<>();
        lookAndFeelSelector.setRenderer(new LookAndFeelRenderer());
        for (UIManager.LookAndFeelInfo theme : customizer.getThemes()) {
            lookAndFeelSelector.addItem(theme);
        }
        JLabel defaultThemeLabel = new JLabel("Default Themes: ");
        defaultThemeLabel.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0));

        JButton selectFileButton = new JButton("Select Theme File...");

        lookAndFeelSelector.addItemListener(e -> {
            if(e.getStateChange() == ItemEvent.SELECTED) {
                selectedThemeFile = null;
                selectFileButton.setText("Select Theme File...");
                try{
                    LookAndFeel theme = customizer.createThemeFromDefaults((UIManager.LookAndFeelInfo) e.getItem(), true);
                    previewPanel.setPreviewTheme(theme);
                }catch (Exception ex){
                    ex.printStackTrace();
                    previewPanel.reset();
                    JOptionPane.showMessageDialog(CustomizerPanel.this, "Could not load the specified theme.\n" + ex.getMessage(), "Burp Customizer", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        JLabel fileThemeLabel = new JLabel("Theme File: ");
        fileThemeLabel.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0));

        selectFileButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setFileFilter(new FileNameExtensionFilter("IntelliJ Theme File (.theme.json)", "json"));
                int res = fileChooser.showOpenDialog(CustomizerPanel.this);
                if(res == JFileChooser.APPROVE_OPTION){
                    selectFileButton.setText(fileChooser.getSelectedFile().getName());
                    try {
                        LookAndFeel theme = customizer.createThemeFromFile(fileChooser.getSelectedFile());
                        previewPanel.setPreviewTheme(theme);
                        selectedThemeFile = fileChooser.getSelectedFile();
                    } catch (IOException | UnsupportedLookAndFeelException ex) {
                        previewPanel.reset();
                        JOptionPane.showMessageDialog(CustomizerPanel.this, "Could not load the specified theme.\n" + ex.getMessage(), "Burp Customizer", JOptionPane.ERROR_MESSAGE);
                    }
                    lookAndFeelSelector.setSelectedItem(null);
                }else{
                    selectFileButton.setText("Select Theme File...");
                }
            }
        });

        JButton applyThemeButton = new JButton(new AbstractAction("Apply") {
            @Override
            public void actionPerformed(ActionEvent e) {
//                SwingUtilities.invokeLater(() -> {
                    if(lookAndFeelSelector.getSelectedItem() != null) {
                        customizer.setTheme((UIManager.LookAndFeelInfo) lookAndFeelSelector.getSelectedItem());
                    }else if(selectedThemeFile != null){
                        customizer.setTheme(selectedThemeFile);
                    }else{
                        JOptionPane.showMessageDialog(CustomizerPanel.this, "No theme selected!", "Burp Customizer", JOptionPane.ERROR_MESSAGE);
                    }
                    viewOnGithubButton.setIcon(getGithubIcon());
//                });
            }
        });
//        applyThemeButton.setMinimumSize(applyThemeButton.getSize());

        if(customizer.getThemeSource() == BurpCustomizer.ThemeSource.BUILTIN && customizer.getSelectedBuiltIn() != null) {
            lookAndFeelSelector.setSelectedItem(customizer.getSelectedBuiltIn());
        } else if(customizer.getThemeSource() == BurpCustomizer.ThemeSource.FILE && customizer.getSelectedThemeFile() != null) {
            lookAndFeelSelector.setSelectedItem(null);
            File selectedFile = customizer.getSelectedThemeFile();
            selectFileButton.setText(selectedFile.getName());
            selectedThemeFile = selectedFile;
        }

        PanelBuilder selectorPanelBuilder = new PanelBuilder();
        selectorPanelBuilder.setComponentGrid(new Component[][]{
                new Component[]{themeLabel, themeLabel},
                new Component[]{defaultThemeLabel, lookAndFeelSelector},
                new Component[]{fileThemeLabel, selectFileButton},
                new Component[]{previewPanel, previewPanel},
                new Component[]{applyThemeButton, applyThemeButton},
        });
        int[][] selectorPanelWeights = new int[][]{
                new int[]{0, 0},
                new int[]{1, 1},
                new int[]{1, 1},
                new int[]{3, 3},
                new int[]{1, 1},
        };
        selectorPanelBuilder.setGridWeightsX(selectorPanelWeights);
        selectorPanelBuilder.setGridWeightsY(selectorPanelWeights);
        selectorPanelBuilder.setAlignment(Alignment.FILL);

        JPanel selectorPanel = selectorPanelBuilder.build();

        JPanel fillerPanel = new JPanel();
        fillerPanel.setMaximumSize(new Dimension(0,0));

        Component[][] componentGrid = new Component[][]{
                new Component[]{headerLabel},
                new Component[]{subtitle},
                new Component[]{separator},
                new Component[]{contactPanel},
                new Component[]{aboutContent},
                new Component[]{selectorPanel},
                new Component[]{fillerPanel},
//                new Component[]{fillerPanel}
        };

        int[][] weightGridY = new int[][]{
                new int[]{0},
                new int[]{0},
                new int[]{0},
                new int[]{0},
                new int[]{0},
                new int[]{0},
                new int[]{1},
        };

        PanelBuilder contentPanelBuilder = new PanelBuilder();
        contentPanelBuilder.setComponentGrid(componentGrid);
        contentPanelBuilder.setGridWeightsX(weightGridY);
        contentPanelBuilder.setGridWeightsY(weightGridY);
        contentPanelBuilder.setScaleX(0.8);
        contentPanelBuilder.setScaleY(1.0);
        contentPanelBuilder.setAlignment(Alignment.FILL);

        JPanel contentPanel = contentPanelBuilder.build();
        contentPanel.setBorder(new EmptyBorder(30, 30, 30, 30));

        JScrollPane scrollPane = new JScrollPane(contentPanel);
        scrollPane.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                contentPanel.setPreferredSize(new Dimension(e.getComponent().getWidth(), contentPanel.getHeight()));
            }
        });
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);

        this.add(scrollPane, BorderLayout.CENTER);
    }

    private ImageIcon getGithubIcon(){
        String githubLogoFilename = "GitHubLogo" +
                (UIManager.getLookAndFeel() instanceof FlatLaf && ((FlatLaf) UIManager.getLookAndFeel()).isDark() ? "White" : "Black")
                + ".png";
        return loadImage(githubLogoFilename, 30, 30);
    }

    private ImageIcon loadImage(String filename, int width, int height){
        ClassLoader cldr = this.getClass().getClassLoader();
        URL imageURLMain = cldr.getResource(filename);

        if(imageURLMain != null) {
            Image scaled = new ImageIcon(imageURLMain).getImage().getScaledInstance(width, height, Image.SCALE_SMOOTH);
            ImageIcon scaledIcon = new ImageIcon(scaled);
            BufferedImage bufferedImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
            Graphics2D g = (Graphics2D) bufferedImage.getGraphics();
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.drawImage(scaledIcon.getImage(), null, null);
            return new ImageIcon(bufferedImage);
        }
        return null;
    }

    private static class LookAndFeelRenderer extends DefaultListCellRenderer {

        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
            UIManager.LookAndFeelInfo lookAndFeelInfo = ((UIManager.LookAndFeelInfo) value);
            return super.getListCellRendererComponent(list, lookAndFeelInfo != null ? lookAndFeelInfo.getName() : "Unknown", index, isSelected, cellHasFocus);
        }
    }
}
