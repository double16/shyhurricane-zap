package com.github.double16;

import org.parosproxy.paros.common.AbstractParam;
import org.parosproxy.paros.core.scanner.Alert;

@SuppressWarnings("serial")
public class ShyHurricaneOptionsParam extends AbstractParam {

    private static final String BASE_KEY = "shyhurricane.";
    private static final String KEY_ONLY_IN_SCOPE = BASE_KEY + "onlyInScope";
    private static final String KEY_SERVER_URL = BASE_KEY + "mcpServerUrl";
    private static final String KEY_MIN_CONF = BASE_KEY + "minConfidence";
    private static final String KEY_MIN_RISK = BASE_KEY + "minRisk";
    private static final String KEY_INITIATORS_ALL = BASE_KEY + "initiators.all";
    private static final String KEY_INITIATORS_SELECTED = BASE_KEY + "initiators.selected"; // CSV of ints

    private boolean onlyInScope = true;
    private String mcpServerUrl = "http://localhost:8000";
    private int minConfidenceLevel = Alert.CONFIDENCE_LOW;
    private int minRiskLevel = Alert.RISK_INFO;
    private boolean initiatorsAll = true;
    private String initiatorsSelectedCsv = ""; // persisted as CSV

    @Override
    protected void parse() {
        onlyInScope = getConfig().getBoolean(KEY_ONLY_IN_SCOPE, onlyInScope);
        mcpServerUrl = getConfig().getString(KEY_SERVER_URL, mcpServerUrl);
        minConfidenceLevel = getConfig().getInt(KEY_MIN_CONF, minConfidenceLevel);
        minRiskLevel = getConfig().getInt(KEY_MIN_RISK, minRiskLevel);
        initiatorsAll = getConfig().getBoolean(KEY_INITIATORS_ALL, initiatorsAll);
        initiatorsSelectedCsv = getConfig().getString(KEY_INITIATORS_SELECTED, initiatorsSelectedCsv);
    }

    public boolean isOnlyInScope() {
        return onlyInScope;
    }

    public void setOnlyInScope(boolean v) {
        onlyInScope = v;
        getConfig().setProperty(KEY_ONLY_IN_SCOPE, v);
    }

    public String getMcpServerUrl() {
        return mcpServerUrl;
    }

    public void setMcpServerUrl(String v) {
        mcpServerUrl = v;
        getConfig().setProperty(KEY_SERVER_URL, v);
    }

    public int getMinConfidenceLevel() {
        return minConfidenceLevel;
    }

    public void setMinConfidenceLevel(int v) {
        minConfidenceLevel = v;
        getConfig().setProperty(KEY_MIN_CONF, v);
    }

    public int getMinRiskLevel() {
        return minRiskLevel;
    }

    public void setMinRiskLevel(int v) {
        minRiskLevel = v;
        getConfig().setProperty(KEY_MIN_RISK, v);
    }

    public boolean isInitiatorsAll() {
        return initiatorsAll;
    }

    public void setInitiatorsAll(boolean v) {
        initiatorsAll = v;
        getConfig().setProperty(KEY_INITIATORS_ALL, v);
    }

    /**
     * Returns a CSV of selected initiator ids (persisted format).
     */
    public String getInitiatorsSelectedCsv() {
        return initiatorsSelectedCsv;
    }

    /**
     * Set by CSV string (persisted format).
     */
    public void setInitiatorsSelectedCsv(String csv) {
        initiatorsSelectedCsv = csv != null ? csv : "";
        getConfig().setProperty(KEY_INITIATORS_SELECTED, initiatorsSelectedCsv);
    }

    /**
     * Utility: check if a given initiator id is in the selected list.
     */
    public boolean isInitiatorSelected(int initiator) {
        if (initiatorsAll) return true;
        for (String s : initiatorsSelectedCsv.split(",")) {
            if (s.isEmpty()) continue;
            try {
                if (Integer.parseInt(s.trim()) == initiator) return true;
            } catch (NumberFormatException ignored) {
                // ignore bad entries
            }
        }
        return false;
    }
}
