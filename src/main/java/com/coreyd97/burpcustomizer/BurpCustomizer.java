package com.coreyd97.burpcustomizer;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import burp.ITab;
import com.formdev.flatlaf.CustomTheme;
import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.IntelliJTheme;
import com.formdev.flatlaf.intellijthemes.FlatAllIJThemes;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Optional;

public class BurpCustomizer implements ITab, IBurpExtender, IExtensionStateListener {

    private boolean compatible;
    private LookAndFeel originalBurpTheme;
    private ArrayList<UIManager.LookAndFeelInfo> themes;
    private UIManager.LookAndFeelInfo selectedTheme;
    private CustomizerPanel ui;
    public static IBurpExtenderCallbacks callbacks;
    JMenuBar menuBar;
    JMenu menuItem;

    public BurpCustomizer(){
        themes = new ArrayList<>(Arrays.asList(FlatAllIJThemes.INFOS));
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpCustomizer.callbacks = callbacks;
        originalBurpTheme = UIManager.getLookAndFeel();
        String theme = callbacks.loadExtensionSetting("theme");
        Optional<UIManager.LookAndFeelInfo> previousTheme =
                themes.stream().filter(lookAndFeelInfo -> lookAndFeelInfo.getClassName().equalsIgnoreCase(theme)).findFirst();


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
            previousTheme.ifPresent(BurpCustomizer.this::setTheme);
            this.ui = new CustomizerPanel(this);

            Arrays.stream(Frame.getFrames()).filter(frame -> frame.getTitle().startsWith("Burp Suite") && frame.isVisible()).findFirst().ifPresent(frame -> {
                frame.setTitle("Burp Customizer - By CoreyD97");
            });

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

    public UIManager.LookAndFeelInfo getSelectedTheme() {
        return selectedTheme;
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
            Class themeClass = Class.forName(lookAndFeelInfo.getClassName());
            IntelliJTheme.ThemeLaf theme = (IntelliJTheme.ThemeLaf) themeClass.getDeclaredConstructor().newInstance();
            LookAndFeel laf = new CustomTheme(theme);

            UIManager.setLookAndFeel(laf);
            FlatLaf.updateUI();
            selectedTheme = lookAndFeelInfo;
            callbacks.saveExtensionSetting("theme", lookAndFeelInfo.getClassName());
        } catch (Exception ex) {
            StringWriter sw = new StringWriter();
            ex.printStackTrace(new PrintWriter(sw));
            callbacks.printError("Could not load theme.");
            callbacks.printError(sw.toString());
            JOptionPane.showMessageDialog(getUiComponent(), "Could not load the specified theme.", "Burp Customizer", JOptionPane.ERROR_MESSAGE);
        }
    }

    @Override
    public void extensionUnloaded() {
        BurpCustomizer.callbacks = null;
        if(menuBar != null && menuItem != null) menuBar.remove(menuItem);
        try {
            UIManager.setLookAndFeel(originalBurpTheme);
            FlatLaf.updateUI();
        } catch (UnsupportedLookAndFeelException e) {
            e.printStackTrace();
        }
    }
}
