package com.github.double16;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Method;
import java.io.StringReader;
import java.io.StringWriter;
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

    @Test
    void statusDefaultsAndPersistence() {
        ShyHurricaneOptionsParam param = new ShyHurricaneOptionsParam();
        for (int group = 2; group <= 5; group++) {
            assertEquals(group == 2, param.isStatusGroupSelected(group));
        }
        XMLConfiguration config = new XMLConfiguration();
        param.load(config);
        for (int group = 2; group <= 5; group++) {
            assertEquals(group == 2, param.isStatusGroupSelected(group));
            param.setStatusGroupSelected(group, group != 2);
            assertEquals(group != 2, config.getBoolean("shyhurricane.statusCodes.group" + group + "xx"));
        }
        ShyHurricaneOptionsParam reloaded = new ShyHurricaneOptionsParam();
        reloaded.load(config);
        for (int group = 2; group <= 5; group++) {
            assertEquals(group != 2, reloaded.isStatusGroupSelected(group));
        }
    }

    @Test
    void statusSettingsSurviveXmlSaveAndReload() throws Exception {
        XMLConfiguration config = new XMLConfiguration();
        ShyHurricaneOptionsParam param = new ShyHurricaneOptionsParam();
        param.load(config);
        for (int group = 2; group <= 5; group++) {
            param.setStatusGroupSelected(group, group != 2);
        }
        StringWriter xml = new StringWriter();
        config.save(xml);
        XMLConfiguration saved = new XMLConfiguration();
        saved.load(new StringReader(xml.toString()));
        ShyHurricaneOptionsParam reloaded = new ShyHurricaneOptionsParam();
        reloaded.load(saved);
        for (int group = 2; group <= 5; group++) {
            assertEquals(group != 2, reloaded.isStatusGroupSelected(group));
        }
    }

    @Test
    void legacyStatusSettingsAreMigratedAndCanBeSaved() throws Exception {
        XMLConfiguration config = new XMLConfiguration();
        for (int group = 2; group <= 5; group++) {
            config.setProperty("shyhurricane.statusCodes." + group + "xx", group != 2);
        }
        // A new key takes precedence if both formats exist.
        config.setProperty("shyhurricane.statusCodes.group3xx", false);
        ShyHurricaneOptionsParam param = new ShyHurricaneOptionsParam();
        param.load(config);
        for (int group = 2; group <= 5; group++) {
            assertEquals(group >= 4, param.isStatusGroupSelected(group));
            assertFalse(config.containsKey("shyhurricane.statusCodes." + group + "xx"));
        }
        StringWriter xml = new StringWriter();
        config.save(xml);
        XMLConfiguration saved = new XMLConfiguration();
        saved.load(new StringReader(xml.toString()));
        param.load(saved);
        for (int group = 2; group <= 5; group++) {
            assertEquals(group >= 4, param.isStatusGroupSelected(group));
        }
    }

    @Test
    void invalidStatusGroupsAreRejectedWithoutChangingSettings() {
        ShyHurricaneOptionsParam param = new ShyHurricaneOptionsParam();
        initializeConfig(param);
        for (int group : new int[]{1, 6}) {
            assertThrows(IllegalArgumentException.class,
                    () -> param.setStatusGroupSelected(group, true));
            assertFalse(param.isStatusGroupSelected(group));
        }
        assertTrue(param.isStatusGroupSelected(2));
    }

    @Test
    void generalSettingsArePersisted() {
        XMLConfiguration config = new XMLConfiguration();
        ShyHurricaneOptionsParam param = new ShyHurricaneOptionsParam();
        param.load(config);
        param.setOnlyInScope(false);
        param.setMcpServerUrl("https://example.test");
        param.setMinConfidenceLevel(Alert.CONFIDENCE_HIGH);
        param.setMinRiskLevel(Alert.RISK_HIGH);
        ShyHurricaneOptionsParam reloaded = new ShyHurricaneOptionsParam();
        reloaded.load(config);
        assertFalse(reloaded.isOnlyInScope());
        assertEquals("https://example.test", reloaded.getMcpServerUrl());
        assertEquals(Alert.CONFIDENCE_HIGH, reloaded.getMinConfidenceLevel());
        assertEquals(Alert.RISK_HIGH, reloaded.getMinRiskLevel());
    }

    @Test
    void statusBoundariesAndEmptySelection() {
        ShyHurricaneOptionsParam param = new ShyHurricaneOptionsParam();
        initializeConfig(param);
        for (int selected = 2; selected <= 5; selected++) {
            for (int group = 2; group <= 5; group++) {
                param.setStatusGroupSelected(group, group == selected);
            }
            for (int code : new int[]{0, 100, 101, 199, 200, 299, 300, 399, 400, 499, 500, 599, 600}) {
                assertEquals(code >= 200 && code <= 599 && code / 100 == selected,
                        param.isStatusCodeSelected(code), "status " + code);
            }
        }
        for (int group = 2; group <= 5; group++) {
            param.setStatusGroupSelected(group, true);
        }
        assertFalse(param.isStatusCodeSelected(199));
        assertFalse(param.isStatusCodeSelected(600));
        for (int group = 2; group <= 5; group++) {
            param.setStatusGroupSelected(group, false);
        }
        for (int code : new int[]{200, 301, 404, 503}) {
            assertFalse(param.isStatusCodeSelected(code));
        }
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
