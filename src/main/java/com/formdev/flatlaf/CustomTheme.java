package com.formdev.flatlaf;

import com.coreyd97.burpcustomizer.BurpCustomizer;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class CustomTheme extends IntelliJTheme.ThemeLaf {

    Class burpDark, burpLight;

    public CustomTheme(IntelliJTheme.ThemeLaf base) throws ClassNotFoundException {
        super(base.getTheme());
        this.burpDark = ClassLoader.getSystemClassLoader().loadClass("burp.theme.BurpDarkLaf");
        this.burpLight = ClassLoader.getSystemClassLoader().loadClass("burp.theme.BurpLightLaf");
    }

    @Override
    public UIDefaults getDefaults() {
        UIDefaults defaults;
        FlatLaf burpBase;
        try {
            if (isDark()) {
                burpBase = (FlatLaf) burpDark.getConstructor().newInstance();
            }else{
                burpBase = (FlatLaf) burpLight.getConstructor().newInstance();
            }
            defaults = burpBase.getDefaults();

        }catch (Exception e){
            defaults = super.getDefaults();
            BurpCustomizer.callbacks.printError("Could not get Burp base theme! - " + e.getMessage());
        }
//        defaults = super.getDefaults(); //Debugging. Uncomment to overwrite all Burp defaults.
        defaults.putAll(super.getDefaults());

        //For some reason, using lazy loading in getAdditionalDefaults for this property causes issues...
        defaults.put("TabbedPane.selectedBackground", defaults.get("TabbedPane.background"));

        return defaults;
    }



    @Override
    protected Properties getAdditionalDefaults() {
        //Add Additional Overrides Here
        Properties defaults = new Properties();
        defaults.put("TabbedPane.tabInsets", "2,15,4,15");
        defaults.put("TabbedPane.tabHeight", "20");
        defaults.put("Burp.selectionBackground", "lazy(Table.selectionBackground)");
        defaults.put("Burp.selectionForeground", "lazy(Table.selectionForeground)");
        defaults.put("Burp.burpOrange", "#0000FF");
        defaults.put("Burp.burpTitle", "lazy(TabbedPane.underlineColor)"); //Request response titles
        defaults.put("Burp.burpError", "lazy(TabbedPane.underlineColor)");
        defaults.put("Burp.currentLineBackground", "#00FF00");
        defaults.put("Burp.selectionBorder", "lazy(Tree.selectionBackground)");
//        defaults.put("Burp.solidForeground", "#FF00FF");
        defaults.put("Burp.tabFlashColour", "lazy(TabbedPane.underlineColor)");
        defaults.put("Burp.border", "lazy(Component.borderColor)");
        defaults.put("Burp.expandableConfigPanelBorder", "lazy(Component.borderColor)");
        defaults.put("Burp.highlightPanelBackground", "lazy(TabbedPane.hoverColor)");
//        defaults.put("Burp.appLoginWarning", "lazy(TabbedPane.underlineColor)");
        defaults.put("Table.alternateRowColor", "lighten(Table.background,5%,lazy)");

        defaults.put("Burp.suiteTabbedPaneBackground", "lazy(TabbedPane.background)");
        defaults.put("Burp.inspectorBackground", "lazy(Panel.background)");
        defaults.put("Burp.inspectorCollapsedBackground", "lazy(Panel.background)");
        defaults.put("Burp.inspectorBorder", "lazy(Component.borderColor)");
        defaults.put("Burp.inspectorTableBackground", "lazy(Table.background)");
        defaults.put("Burp.inspectorTableHeadingBackground", "lazy(TableHeader.background)");
        defaults.put("Burp.inspectorTableRowHighlightBackground", "lazy(Table.selectionBackground)");
        defaults.put("Burp.inspectorTableRowHighlightActionBackground", "lazy(Table.dropCellBackground)");
        defaults.put("Burp.inspectorTableEntryNameForeground", "lazy(Table.foreground)");
        defaults.put("Burp.inspectorTableEntryValueForeground", "lazy(Table.focusCellForeground)");
        defaults.put("Burp.inspectorTableEditableFieldBackground", "lazy(TextField.background)"); //TOFIX
        defaults.put("Burp.inspectorEmptyCollapsedViewLabelForeground", "lazy(Label.foreground)");
//        defaults.put("Burp.inspectorSeeMoreHoverBackground", "#7DFF15FF");
//        defaults.put("Burp.inspectorSeeMorePressedBackground", "#1DB485FF");
        defaults.put("TabbedPane.selectedBackground", "lazy(TabbedPane.background)");

        defaults.put("Burp.filterBarForeground", "lazy(TextField.foreground)");
        defaults.put("Burp.filterBarBackground", "lazy(TextField.background)");
        defaults.put("Burp.clueTextForeground", "lazy(TextField.placeholderForeground)");
//        defaults.put("Burp.healthcheckSuccess", new Color(7, 8, 126));
//        defaults.put("Burp.healthcheckWarning", new Color(129, 38, 81));
//        defaults.put("Burp.healthcheckFail", new Color(120, 133, 252));
        defaults.put("Burp.searchHighlightColour", "lazy(SearchMatch.startBackground)");
        defaults.put("Burp.alertHighlightColour", "lazy(Component.focusColor)");
        defaults.put("Burp.defaultFixedHighlightColour", "lazy(Component.error.focusedBorderColor)"); //Issues Panel Highlight
//        defaults.put("Burp.intruderHighlight", "#F37985FF");
//        defaults.put("Burp.mapNodeEmpty", new Color(53, 214, 237));
//        defaults.put("Burp.mapNodeError", new Color(71, 133, 70));
//        defaults.put("Burp.mapNodeRequested", new Color(43, 127, 51));
//        defaults.put("Burp.mapNodeNotRequested", new Color(111, 250, 64));
        defaults.put("Burp.primaryButtonForeground", "lazy(Button.default.foreground)");
        defaults.put("Burp.primaryButtonBackground", "lazy(Button.default.startBackground)");
        defaults.put("Burp.actionPanelBackground", "lazy(Button.startBackground)");
        defaults.put("Burp.actionPanelHoverBackground", "lazy(Button.hoverBackground)");
        defaults.put("Burp.actionPanelBorder", "lazy(Button.borderColor)");
        defaults.put("Burp.standoutPanelBackground", "lazy(Button.startBackground)");
        defaults.put("Burp.standoutPanelHoverBackground", "lazy(Button.hoverBackground)");
        defaults.put("Burp.proUpsellForeground", "lazy(Button.foreground)");
        defaults.put("Burp.proUpsellBackground", "lazy(Button.background)");

        //Repeater pretty / raw buttons
        defaults.put("Burp.radioBarActiveForeground", "lazy(ToggleButton.foreground)");
        defaults.put("Burp.radioBarActiveBackground", "lazy(ToggleButton.pressedBackground)");
        defaults.put("Burp.radioBarHoverForeground", "lazy(ToggleButton.selectedForeground)");
        defaults.put("Burp.radioBarHoverBackground", "lazy(ToggleButton.toolbar.hoverBackground)");
        defaults.put("Burp.radioBarInactiveForeground", "lazy(ToggleButton.foreground)");
        defaults.put("Burp.radioBarInactiveBackground", "lazy(ToggleButton.startBackground)");
        defaults.put("Burp.radioBarDisabledForeground", "lazy(ToggleButton.disabledText)");
        defaults.put("Burp.radioBarDivider", "lazy(Component.borderColor)");

        defaults.put("Burp.requestResponseTabBorder", "lazy(TabbedPane.underlineColor)");
        defaults.put("Burp.requestResponseTabInactiveForeground", "lazy(TabbedPane.foreground)");
        defaults.put("Burp.requestResponseTabInactiveBackground", "lazy(TabbedPane.background)");
        defaults.put("Burp.requestResponseTabHoverBackground", "lazy(TabbedPane.buttonHoverBackground)");
        defaults.put("Burp.ribbonPanelBorder", "lazy(Component.borderColor)");
        defaults.put("Burp.ribbonButtonForeground", "lazy(TabbedPane.foreground)");
        defaults.put("Burp.ribbonButtonHoverForeground", "lazy(TabbedPane.foreground)");
        defaults.put("Burp.ribbonButtonSelectedForeground", "lazy(TabbedPane.foreground)");
        defaults.put("Burp.ribbonButtonInactiveForeground", "lazy(TabbedPane.foreground)");
        defaults.put("Burp.ribbonButtonBackground", "lazy(TabbedPane.background)");
        defaults.put("Burp.ribbonButtonSelectedBackground", "lazy(TabbedPane.buttonPressedBackground)");
        defaults.put("Burp.ribbonButtonHoverBackground", "lazy(TabbedPane.buttonHoverBackground)");
        defaults.put("Burp.ribbonButtonSelectedHoverBackground", "lazy(TabbedPane.background)");
//        defaults.put("Burp.scanPhaseInactiveForeground", new Color(94, 240, 216));
//        defaults.put("Burp.scanPhaseInactiveBackground", new Color(173, 42, 120));
        defaults.put("Burp.htmlLinkForeground", "lazy(Component.linkColor)");
//        defaults.put("Burp.severityHigh", new Color(190, 50, 41));
//        defaults.put("Burp.severityMedium", new Color(240, 246, 179));
//        defaults.put("Burp.severityLow", new Color(24, 23, 46));
//        defaults.put("Burp.severityInfo", new Color(110, 146, 124));
        defaults.put("Burp.actionNormal", "lazy(Button.startBackground)");
        defaults.put("Burp.actionHover", "lazy(Button.default.focusColor)");
        defaults.put("Burp.actionPressed", "lazy(Button.endBackground)");
        defaults.put("Burp.taskActionNormal", "lazy(Button.foreground)");
        defaults.put("Burp.taskActionHover", "lazy(Button.default.focusColor)");
        defaults.put("Burp.taskActionPressed", "lazy(Button.default.focusColor)");
        defaults.put("Burp.taskListHeaderBackground", "lazy(TextField.background)");
//        defaults.put("Burp.textEditorText", new Color(199, 166, 0));
//        defaults.put("Burp.textEditorReservedWord", new Color(133, 102, 103));
//        defaults.put("Burp.textEditorReservedWord2", new Color(215, 231, 67));
//        defaults.put("Burp.textEditorAnnotation", new Color(16, 144, 176));
//        defaults.put("Burp.textEditorComment", new Color(242, 158, 157));
//        defaults.put("Burp.textEditorDataType", new Color(18, 9, 64));
//        defaults.put("Burp.textEditorFunction", new Color(44, 206, 26));
//        defaults.put("Burp.textEditorLiteralBoolean", new Color(167, 96, 58));
//        defaults.put("Burp.textEditorLiteralNumber", new Color(120, 89, 109));
//        defaults.put("Burp.textEditorLiteralQuote", new Color(19, 99, 205));
//        defaults.put("Burp.textEditorLiteralString", new Color(6, 241, 150));
//        defaults.put("Burp.textEditorTagDelimiter", new Color(74, 62, 23));
//        defaults.put("Burp.textEditorTagName", new Color(105, 141, 66));
//        defaults.put("Burp.textEditorProcessingInstruction", new Color(180, 28, 105));
//        defaults.put("Burp.textEditorCdataDelimiter", new Color(253, 122, 150));
//        defaults.put("Burp.textEditorCdata", new Color(82, 214, 219));
//        defaults.put("Burp.textEditorEntityReference", new Color(161, 177, 189));
//        defaults.put("Burp.textEditorOperator", new Color(129, 124, 174));
//        defaults.put("Burp.textEditorPreProcessor", new Color(60, 2, 213));
//        defaults.put("Burp.textEditorRegex", new Color(140, 48, 96));
//        defaults.put("Burp.textEditorSeparator", new Color(103, 136, 117));
//        defaults.put("Burp.textEditorVariable", new Color(61, 208, 91));
//        defaults.put("Burp.textEditorHttpFirstLine", new Color(81, 233, 219));
//        defaults.put("Burp.textEditorHeaderName", new Color(22, 44, 200));
//        defaults.put("Burp.textEditorHeaderValue", new Color(8, 41, 15));
//        defaults.put("Burp.textEditorParamName", new Color(108, 25, 179));
//        defaults.put("Burp.textEditorParamValue", new Color(110, 254, 101));
//        defaults.put("Burp.textEditorCookieName", new Color(55, 250, 77));
//        defaults.put("Burp.textEditorCookieValue", new Color(203, 220, 154));
        defaults.put("Burp.textEditorBackground", "lazy(TextArea.background)");
        defaults.put("Burp.textEditorCurrentLineBackground", "lazy(EditorPane.inactiveBackground)");
        defaults.put("Burp.textEditorSelectionBackground", "lazy(TextArea.selectionBackground)");
        defaults.put("Burp.textEditorSelectionForeground", "lazy(TextArea.selectionForeground)");
        defaults.put("Burp.textEditorGutterBorder", "lazy(Component.borderColor)");
        defaults.put("Burp.textEditorLineNumbers", "lazy(TextField.placeholderForeground)");
        defaults.put("Burp.textEditorLozengeBackground", "lazy(Button.default.endBackground)"); //Newline indicators
        defaults.put("Burp.textEditorLozengeText", "lazy(Button.default.foreground)");       //Newline indicators
//        defaults.put("Burp.warningBarForeground", "#E29408FF");
//        defaults.put("Burp.warningBarBackground", "#1255C6FF");
        return defaults;
    }
}
