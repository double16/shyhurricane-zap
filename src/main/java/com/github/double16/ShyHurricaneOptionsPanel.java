package com.github.double16;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.view.AbstractParamPanel;

/**
 * Options panel for ShyHurricane Forwarder.
 * Placed under: Tools ▸ Options ▸ ShyHurricane Forwarder
 */
@SuppressWarnings("serial")
public class ShyHurricaneOptionsPanel extends AbstractParamPanel {

    private final ExtensionShyHurricaneForwarder extension;

    private final JCheckBox chkOnlyInScope = new JCheckBox("Only forward in-scope traffic");
    private final JTextField txtMcpServerUrl = new JTextField(100);

    private static final String[] CONFIDENCE_LABELS = {
            "False Positive", "Low", "Medium", "High", "User-Confirmed"
    };
    private static final int[] CONFIDENCE_VALUES = {
            Alert.CONFIDENCE_FALSE_POSITIVE,
            Alert.CONFIDENCE_LOW,
            Alert.CONFIDENCE_MEDIUM,
            Alert.CONFIDENCE_HIGH,
            Alert.CONFIDENCE_USER_CONFIRMED
    };
    private final JComboBox<String> cmbConfidence =
            new JComboBox<>(CONFIDENCE_LABELS);

    private static final String[] RISK_LABELS = {"Info", "Low", "Medium", "High"};
    private static final int[] RISK_VALUES = {
            Alert.RISK_INFO, Alert.RISK_LOW, Alert.RISK_MEDIUM, Alert.RISK_HIGH
    };
    private final JComboBox<String> cmbRisk = new JComboBox<>(RISK_LABELS);

    public ShyHurricaneOptionsPanel(ExtensionShyHurricaneForwarder ext) {
        this.extension = ext;
        setName("ShyHurricane");           // tab title
        setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(6, 6, 6, 6);

        // Only-in-scope
        add(chkOnlyInScope, gbc);

        // MCP server URL
        gbc.gridy++;
        add(new JLabel("MCP server URL:"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        add(txtMcpServerUrl, gbc);

        // Minimum confidence
        gbc.gridx = 0;
        gbc.weightx = 0;
        gbc.gridy++;
        gbc.fill = GridBagConstraints.NONE;
        add(new JLabel("Minimum confidence:"), gbc);
        gbc.gridx = 1;
        add(cmbConfidence, gbc);

        // Minimum risk
        gbc.gridx = 0;
        gbc.gridy++;
        add(new JLabel("Minimum risk:"), gbc);
        gbc.gridx = 1;
        add(cmbRisk, gbc);

        // stretch the last column a bit
        gbc.gridx = 0;
        gbc.gridy++;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridx = 2;
        add(new JPanel(), gbc);
    }

    @Override
    public void initParam(Object ignored) {
        // populate UI from the current extension state
        chkOnlyInScope.setSelected(extension.isOnlyInScope());
        txtMcpServerUrl.setText(extension.getMcpServerUrl());

        cmbConfidence.setSelectedIndex(
                indexOf(CONFIDENCE_VALUES, extension.getMinimumConfidenceLevel()));
        cmbRisk.setSelectedIndex(
                indexOf(RISK_VALUES, extension.getMinimumRiskLevel()));
    }

    @Override
    public void saveParam(Object ignored) {
        // push UI values back into the extension
        extension.setOnlyInScope(chkOnlyInScope.isSelected());
        extension.setMcpServerUrl(txtMcpServerUrl.getText().trim());
        extension.setMinimumConfidenceLevel(
                CONFIDENCE_VALUES[cmbConfidence.getSelectedIndex()]);
        extension.setMinimumRiskLevel(
                RISK_VALUES[cmbRisk.getSelectedIndex()]);
    }

    @Override
    public String getHelpIndex() {
        return null; // no help page
    }

    private static int indexOf(int[] arr, int value) {
        for (int i = 0; i < arr.length; i++) {
            if (arr[i] == value) return i;
        }
        return 0;
    }
}
