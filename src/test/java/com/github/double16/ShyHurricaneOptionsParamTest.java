package com.github.double16;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Method;
import org.apache.commons.configuration.FileConfiguration;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.commons.configuration.XMLConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;

class ShyHurricaneOptionsParamTest {

    @Test
    @DisplayName("Defaults are correct on new instance")
    void defaultsAreCorrect() {
        ShyHurricaneOptionsParam p = new ShyHurricaneOptionsParam();
        // Default getters (before parse) should reflect field defaults
        assertTrue(p.isOnlyInScope());
        assertEquals("http://localhost:8000", p.getMcpServerUrl());
        assertEquals(Alert.CONFIDENCE_LOW, p.getMinConfidenceLevel());
        assertEquals(Alert.RISK_INFO, p.getMinRiskLevel());
        assertTrue(p.isInitiatorsAll());
        assertEquals("", p.getInitiatorsSelectedCsv());
        // With initiatorsAll=true any id is considered selected
        assertTrue(p.isInitiatorSelected(0));
        assertTrue(p.isInitiatorSelected(123));
    }

    @Test
    @DisplayName("CSV parsing respects initiatorsAll flag and ignores bad entries")
    void csvParsingAndSelection() {
        ShyHurricaneOptionsParam p = new ShyHurricaneOptionsParam();
        // Initialize underlying config to avoid NPEs in setters
        initializeConfig(p);
        // Turn off the 'all' shortcut
        p.setInitiatorsAll(false);
        p.setInitiatorsSelectedCsv("1, 2, abc,3,, 5");

        assertEquals("1, 2, abc,3,, 5", p.getInitiatorsSelectedCsv());
        assertTrue(p.isInitiatorSelected(1));
        assertTrue(p.isInitiatorSelected(2));
        assertTrue(p.isInitiatorSelected(3));
        assertTrue(p.isInitiatorSelected(5));
        assertFalse(p.isInitiatorSelected(4));
        // Non-numeric 'abc' is ignored (does not throw)
        assertFalse(p.isInitiatorSelected(999));
    }

    @Test
    @DisplayName("Null CSV is treated as empty string and no selection when 'all' is false")
    void nullCsvHandledAsEmpty() {
        ShyHurricaneOptionsParam p = new ShyHurricaneOptionsParam();
        // Initialize underlying config to avoid NPEs in setters
        initializeConfig(p);
        p.setInitiatorsAll(false);
        p.setInitiatorsSelectedCsv(null);

        assertEquals("", p.getInitiatorsSelectedCsv());
        assertFalse(p.isInitiatorSelected(0));
        assertFalse(p.isInitiatorSelected(10));
    }

    @Test
    @DisplayName("parse() reads values from underlying configuration")
    void parseReadsFromConfig() throws Exception {
        ShyHurricaneOptionsParam p = new ShyHurricaneOptionsParam();

        // Initialize config using AbstractParam#load(FileConfiguration)
        FileConfiguration cfg = createConfigInstance();
        if (cfg instanceof XMLConfiguration) {
            ((XMLConfiguration) cfg).setDelimiterParsingDisabled(true);
        }
        Method loadM = Class.forName("org.parosproxy.paros.common.AbstractParam")
                .getMethod("load", FileConfiguration.class);
        loadM.invoke(p, cfg);

        // Access the protected configuration via reflection to seed values
        Method getConfigM = Class.forName("org.parosproxy.paros.common.AbstractParam")
                .getDeclaredMethod("getConfig");
        getConfigM.setAccessible(true);
        Object cfgObj = getConfigM.invoke(p);
        assertInstanceOf(HierarchicalConfiguration.class, cfgObj);
        HierarchicalConfiguration cfgH = (HierarchicalConfiguration) cfgObj;

        cfgH.setProperty("shyhurricane.onlyInScope", false);
        cfgH.setProperty("shyhurricane.mcpServerUrl", "https://example.test:8443");
        cfgH.setProperty("shyhurricane.minConfidence", Alert.CONFIDENCE_HIGH);
        cfgH.setProperty("shyhurricane.minRisk", Alert.RISK_HIGH);
        cfgH.setProperty("shyhurricane.initiators.all", false);
        cfgH.setProperty("shyhurricane.initiators.selected", "7,8,9");

        // Now parse and verify values loaded
        p.parse();

        assertFalse(p.isOnlyInScope());
        assertEquals("https://example.test:8443", p.getMcpServerUrl());
        assertEquals(Alert.CONFIDENCE_HIGH, p.getMinConfidenceLevel());
        assertEquals(Alert.RISK_HIGH, p.getMinRiskLevel());
        assertFalse(p.isInitiatorsAll());
        assertEquals("7,8,9", p.getInitiatorsSelectedCsv());
        assertTrue(p.isInitiatorSelected(8));
        assertFalse(p.isInitiatorSelected(10));
    }

    private static void initializeConfig(ShyHurricaneOptionsParam param) {
        try {
            FileConfiguration cfg = createConfigInstance();
            Method loadM = Class.forName("org.parosproxy.paros.common.AbstractParam")
                    .getMethod("load", FileConfiguration.class);
            loadM.invoke(param, cfg);
        } catch (Exception e) {
            throw new AssertionError("Failed to initialize configuration", e);
        }
    }

    private static FileConfiguration createConfigInstance() {
        return new XMLConfiguration();
    }
}
