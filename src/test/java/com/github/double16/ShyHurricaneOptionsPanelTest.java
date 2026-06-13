package com.github.double16;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ShyHurricaneOptionsPanelTest {

    private FakeExt ext;
    private ShyHurricaneOptionsPanel panel;

    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
    }

    @BeforeEach
    void setUp() {
        ext = new FakeExt();
        panel = new ShyHurricaneOptionsPanel(ext);
    }

    @Test
    void initParam_populatesUiFromExtension() throws Exception {
        ext.onlyInScope = true;
        ext.mcpUrl = "http://localhost:9000";
        ext.minConfidence = org.parosproxy.paros.core.scanner.Alert.CONFIDENCE_HIGH; // index 3
        ext.minRisk = org.parosproxy.paros.core.scanner.Alert.RISK_LOW; // index 1
        ext.initiatorsAll = false;

        // Select one discovered initiator id (if any) to verify selection mapping
        @SuppressWarnings("unchecked")
        Map<Integer, JCheckBox> boxes = (Map<Integer, JCheckBox>) getField(panel, "initiatorBoxes");
        String oneIdCsv = boxes.keySet().stream().findFirst().map(String::valueOf).orElse("");
        ext.initiatorsCsv = oneIdCsv;

        panel.initParam(null);

        JCheckBox chkOnlyInScope = (JCheckBox) getField(panel, "chkOnlyInScope");
        JTextField txtMcpServerUrl = (JTextField) getField(panel, "txtMcpServerUrl");
        @SuppressWarnings("unchecked")
        JComboBox<String> cmbConfidence = (JComboBox<String>) getField(panel, "cmbConfidence");
        @SuppressWarnings("unchecked")
        JComboBox<String> cmbRisk = (JComboBox<String>) getField(panel, "cmbRisk");
        JCheckBox chkAllInitiators = (JCheckBox) getField(panel, "chkAllInitiators");

        assertTrue(chkOnlyInScope.isSelected());
        assertEquals("http://localhost:9000", txtMcpServerUrl.getText());
        assertEquals(3, cmbConfidence.getSelectedIndex());
        assertEquals(1, cmbRisk.getSelectedIndex());
        assertFalse(chkAllInitiators.isSelected());

        if (!oneIdCsv.isEmpty()) {
            Integer id = Integer.valueOf(oneIdCsv);
            assertTrue(boxes.get(id).isSelected());
        }
    }

    @Test
    void saveParam_pushesValuesIntoExtension() throws Exception {
        panel.initParam(null);

        JCheckBox chkOnlyInScope = (JCheckBox) getField(panel, "chkOnlyInScope");
        JTextField txtMcpServerUrl = (JTextField) getField(panel, "txtMcpServerUrl");
        @SuppressWarnings("unchecked")
        JComboBox<String> cmbConfidence = (JComboBox<String>) getField(panel, "cmbConfidence");
        @SuppressWarnings("unchecked")
        JComboBox<String> cmbRisk = (JComboBox<String>) getField(panel, "cmbRisk");
        JCheckBox chkAllInitiators = (JCheckBox) getField(panel, "chkAllInitiators");
        @SuppressWarnings("unchecked")
        Map<Integer, JCheckBox> boxes = (Map<Integer, JCheckBox>) getField(panel, "initiatorBoxes");

        // Set UI values
        chkOnlyInScope.setSelected(true);
        txtMcpServerUrl.setText(" https://srv/endpoint ");
        cmbConfidence.setSelectedIndex(2); // Medium
        cmbRisk.setSelectedIndex(2); // Medium

        // Choose first two initiators explicitly
        List<Integer> chosen = new ArrayList<>();
        for (Integer id : boxes.keySet()) {
            boxes.get(id).setSelected(true);
            chosen.add(id);
            if (chosen.size() == 2) break;
        }

        panel.saveParam(null);

        assertTrue(ext.onlyInScope);
        assertEquals("https://srv/endpoint", ext.mcpUrl); // trimmed
        assertEquals(org.parosproxy.paros.core.scanner.Alert.CONFIDENCE_MEDIUM, ext.minConfidence);
        assertEquals(org.parosproxy.paros.core.scanner.Alert.RISK_MEDIUM, ext.minRisk);
        assertFalse(ext.initiatorsAll);

        if (chosen.size() == 2) {
            // Order preserved in joinCsv
            String[] parts = ext.initiatorsCsv.split(",");
            assertEquals(String.valueOf(chosen.get(0)), parts[0]);
            assertEquals(String.valueOf(chosen.get(1)), parts[1]);
        }

        // Now toggle All initiators and ensure CSV cleared
        chkAllInitiators.doClick();
        panel.saveParam(null);
        assertTrue(ext.initiatorsAll);
        assertEquals("", ext.initiatorsCsv);
    }

    @Test
    void allInitiatorsToggle_enablesAndDisablesBoxes() throws Exception {
        ext.initiatorsAll = false;
        panel.initParam(null);

        JCheckBox chkAllInitiators = (JCheckBox) getField(panel, "chkAllInitiators");
        @SuppressWarnings("unchecked")
        Map<Integer, JCheckBox> boxes = (Map<Integer, JCheckBox>) getField(panel, "initiatorBoxes");

        // Initially enabled
        if (!boxes.isEmpty()) {
            assertTrue(boxes.values().iterator().next().isEnabled());
        }

        // Click to select All -> boxes disabled
        chkAllInitiators.doClick();
        if (!boxes.isEmpty()) {
            assertFalse(boxes.values().iterator().next().isEnabled());
        }

        // Click again -> enabled
        chkAllInitiators.doClick();
        if (!boxes.isEmpty()) {
            assertTrue(boxes.values().iterator().next().isEnabled());
        }
    }

    @Test
    void prettyInitiatorLabel_formatsNicely() throws Exception {
        String s = (String) invokePrivateStatic(ShyHurricaneOptionsPanel.class,
                "prettyInitiatorLabel", new Class[]{String.class}, "ACTIVE_SCANNER");
        assertEquals("Active Scanner", s);
    }

    @Test
    void parseCsv_and_joinCsv_handleValues() throws Exception {
        @SuppressWarnings("unchecked")
        List<Integer> parsed = (List<Integer>) invokePrivateStatic(ShyHurricaneOptionsPanel.class,
                "parseCsv", new Class[]{String.class}, "1, 2, x , 3");
        assertEquals(List.of(1, 2, 3), parsed);

        String csv = (String) invokePrivateStatic(ShyHurricaneOptionsPanel.class,
                "joinCsv", new Class[]{List.class}, parsed);
        assertEquals("1,2,3", csv);
    }

    // ---- helpers ----
    private static Object getField(Object target, String name) throws NoSuchFieldException, IllegalAccessException {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(target);
    }

    private static Object invokePrivateStatic(Class<?> cls, String name, Class<?>[] paramTypes, Object... args)
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Method m = cls.getDeclaredMethod(name, paramTypes);
        m.setAccessible(true);
        return m.invoke(null, args);
    }

    private static class FakeExt extends ExtensionShyHurricaneForwarder {
        boolean onlyInScope;
        String mcpUrl = "";
        int minConfidence = org.parosproxy.paros.core.scanner.Alert.CONFIDENCE_LOW;
        int minRisk = org.parosproxy.paros.core.scanner.Alert.RISK_INFO;
        boolean initiatorsAll;
        String initiatorsCsv = "";

        @Override public boolean isOnlyInScope() { return onlyInScope; }
        @Override public void setOnlyInScope(boolean v) { onlyInScope = v; }

        @Override public String getMcpServerUrl() { return mcpUrl; }
        @Override public void setMcpServerUrl(String url) { mcpUrl = url; }

        @Override public int getMinimumConfidenceLevel() { return minConfidence; }
        @Override public void setMinimumConfidenceLevel(int v) { minConfidence = v; }

        @Override public int getMinimumRiskLevel() { return minRisk; }
        @Override public void setMinimumRiskLevel(int v) { minRisk = v; }

        @Override public boolean isInitiatorsAll() { return initiatorsAll; }
        @Override public void setInitiatorsAll(boolean v) { initiatorsAll = v; }

        @Override public String getInitiatorsSelectedCsv() { return initiatorsCsv; }
        @Override public void setInitiatorsSelectedCsv(String v) { initiatorsCsv = v; }
    }
}
