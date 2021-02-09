package com.coreyd97.burpcustomizer;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import burp.ITab;
import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.IntelliJTheme;
import com.formdev.flatlaf.intellijthemes.FlatAllIJThemes;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Optional;

public class BurpCustomizer implements ITab, IBurpExtender, IExtensionStateListener {

    enum ThemeSource {BUILTIN, FILE}
    private boolean compatible;
    private LookAndFeel originalBurpTheme;
    private ArrayList<UIManager.LookAndFeelInfo> themes;
    private UIManager.LookAndFeelInfo selectedBuiltIn;
    private File selectedThemeFile;
    private ThemeSource themeSource;
    private CustomizerPanel ui;
    public static IBurpExtenderCallbacks callbacks;
    JMenuBar menuBar;
    JMenu menuItem;

    public BurpCustomizer(){
        themes = new ArrayList<>(Arrays.asList(FlatAllIJThemes.INFOS));
        themes.sort(Comparator.comparing(UIManager.LookAndFeelInfo::getName));
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpCustomizer.callbacks = callbacks;
        originalBurpTheme = UIManager.getLookAndFeel();

        String sourceEnum = callbacks.loadExtensionSetting("source");
        if(sourceEnum == null || sourceEnum.equalsIgnoreCase("")){
            themeSource = ThemeSource.BUILTIN;
        }else {
            themeSource = ThemeSource.valueOf(sourceEnum);
        }

        String builtIn = callbacks.loadExtensionSetting("theme");
        Optional<UIManager.LookAndFeelInfo> previousTheme =
                themes.stream().filter(lookAndFeelInfo -> lookAndFeelInfo.getClassName().equalsIgnoreCase(builtIn)).findFirst();
        if(previousTheme.isPresent()) selectedBuiltIn = previousTheme.get();

        String themeFilePref = callbacks.loadExtensionSetting("themeFile");
        if(themeFilePref != null && !themeFilePref.equalsIgnoreCase("")){
            selectedThemeFile = new File(themeFilePref);
            if(!selectedThemeFile.exists()) selectedThemeFile = null;
        }


        try{
            ClassLoader.getSystemClassLoader().loadClass("burp.theme.BurpDarkLaf");
            compatible = true;
        } catch (ClassNotFoundException e) {
            compatible = false;
        }

        try {
            Class inspector = Class.forName("com.formdev.flatlaf.extras.FlatInspector");
            Method install = inspector.getMethod("install", String.class);
            install.invoke(null,"ctrl shift alt X");
        }catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            //Could not install inspector. Probably not in testCompile.
        }

        SwingUtilities.invokeLater(() -> {
            if(themeSource == ThemeSource.BUILTIN && selectedBuiltIn != null){
                setTheme(selectedBuiltIn);
            }else if(themeSource == ThemeSource.FILE && selectedThemeFile != null){
                setTheme(selectedThemeFile);
            }
            this.ui = new CustomizerPanel(this);

//            Arrays.stream(Frame.getFrames()).filter(frame -> frame.getTitle().startsWith("Burp Suite") && frame.isVisible() && frame.getMenuBar() != null).findFirst().ifPresent(frame -> {
//                menuItem = new JMenu("Customize");
//                menuItem.addMouseListener(new MouseAdapter() {
//                    @Override
//                    public void mouseClicked(MouseEvent e) {
//                        setTheme(selectedTheme);
//                    }
//                });
//                menuBar = ((JFrame) frame).getJMenuBar();
//                if(menuBar != null) {
//                    menuBar.add(menuItem);
//                }
//            });

            callbacks.registerExtensionStateListener(this::extensionUnloaded);
            callbacks.addSuiteTab(this);
        });
    }

    @Override
    public String getTabCaption() {
        return "Customizer";
    }

    @Override
    public Component getUiComponent() {
        return this.ui;
    }

    public UIManager.LookAndFeelInfo getSelectedBuiltIn() {
        return selectedBuiltIn;
    }

    public File getSelectedThemeFile() {
        return selectedThemeFile;
    }

    public ThemeSource getThemeSource(){
        return this.themeSource;
    }

    public ArrayList<UIManager.LookAndFeelInfo> getThemes(){
        return this.themes;
    }

    public boolean isCompatible() {
        return compatible;
    }

    public void setTheme(UIManager.LookAndFeelInfo lookAndFeelInfo){
        if(!compatible) return;
        try {
            LookAndFeel laf = createThemeFromDefaults(lookAndFeelInfo);

            UIManager.setLookAndFeel(laf);
            FlatLaf.updateUI();
            selectedBuiltIn = lookAndFeelInfo;
            callbacks.saveExtensionSetting("theme", lookAndFeelInfo.getClassName());
            callbacks.saveExtensionSetting("source", ThemeSource.BUILTIN.toString());
        } catch (Exception ex) {
            StringWriter sw = new StringWriter();
            ex.printStackTrace(new PrintWriter(sw));
            callbacks.printError("Could not load theme.");
            callbacks.printError(sw.toString());
            JOptionPane.showMessageDialog(getUiComponent(), "Could not load the specified theme.\n" + ex.getMessage(), "Burp Customizer", JOptionPane.ERROR_MESSAGE);
        }
    }

    public LookAndFeel createThemeFromDefaults(UIManager.LookAndFeelInfo lookAndFeelInfo) throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        Class themeClass = Class.forName(lookAndFeelInfo.getClassName());
        IntelliJTheme.ThemeLaf theme = (IntelliJTheme.ThemeLaf) themeClass.getDeclaredConstructor().newInstance();
        return new CustomTheme(theme);
    }

    public void setTheme(File themeJsonFile){
        try {
            LookAndFeel lookAndFeel = createThemeFromFile(themeJsonFile);

            UIManager.setLookAndFeel(lookAndFeel);
            FlatLaf.updateUI();

            selectedThemeFile = themeJsonFile;
            callbacks.saveExtensionSetting("themeFile", themeJsonFile.getAbsolutePath());
            callbacks.saveExtensionSetting("source", ThemeSource.FILE.toString());
        } catch (IOException | UnsupportedLookAndFeelException ex) {
            StringWriter sw = new StringWriter();
            ex.printStackTrace(new PrintWriter(sw));
            callbacks.printError("Could not load theme.");
            callbacks.printError(sw.toString());
            JOptionPane.showMessageDialog(getUiComponent(), "Could not load the specified theme:\n" + ex.getMessage(), "Burp Customizer", JOptionPane.ERROR_MESSAGE);
        }
    }

    public LookAndFeel createThemeFromFile(File themeJsonFile) throws IOException, UnsupportedLookAndFeelException {
        IntelliJTheme intelliJTheme = new IntelliJTheme(new FileInputStream(themeJsonFile));
        IntelliJTheme.ThemeLaf fileTheme = new IntelliJTheme.ThemeLaf(intelliJTheme);
        if(intelliJTheme.name == null && intelliJTheme.author == null){
            throw new UnsupportedLookAndFeelException(themeJsonFile.getName() + " does not appear to be a valid theme file.\n" +
                    "If it is, make sure it has a json attribute \"name\".");
        }

        return new CustomTheme(fileTheme);
    }

    @Override
    public void extensionUnloaded() {
        BurpCustomizer.callbacks = null;
        if(menuBar != null && menuItem != null) menuBar.remove(menuItem);
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(originalBurpTheme);
                FlatLaf.updateUI();
            } catch (UnsupportedLookAndFeelException e) {}
        });
    }
}
