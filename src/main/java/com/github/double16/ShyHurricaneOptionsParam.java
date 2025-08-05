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

    private boolean onlyInScope = true;
    private String mcpServerUrl = "http://localhost:8000";
    private int minConfidenceLevel = Alert.CONFIDENCE_MEDIUM;
    private int minRiskLevel = Alert.RISK_INFO;

    @Override
    protected void parse() {
        onlyInScope = getConfig().getBoolean(KEY_ONLY_IN_SCOPE, onlyInScope);
        mcpServerUrl = getConfig().getString(KEY_SERVER_URL, mcpServerUrl);
        minConfidenceLevel = getConfig().getInt(KEY_MIN_CONF, minConfidenceLevel);
        minRiskLevel = getConfig().getInt(KEY_MIN_RISK, minRiskLevel);
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
}
