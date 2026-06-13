package com.github.double16;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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

    // Initiators filtering UI
    private final JCheckBox chkAllInitiators = new JCheckBox("All request initiators");
    private final JPanel initiatorsPanel = new JPanel(new GridBagLayout());
    private final Map<Integer, JCheckBox> initiatorBoxes = new LinkedHashMap<>();

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

        // Divider / label for initiators
        gbc.gridx = 0;
        gbc.gridy++;
        add(new JLabel("Forward requests from:"), gbc);

        // All initiators checkbox
        gbc.gridx = 1;
        add(chkAllInitiators, gbc);

        // Per-initiator checkboxes panel
        gbc.gridx = 0;
        gbc.gridy++;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        add(initiatorsPanel, gbc);

        buildInitiatorCheckboxes();

        // Enable/disable individual boxes when All toggled
        chkAllInitiators.addActionListener(e -> setInitiatorBoxesEnabled(!chkAllInitiators.isSelected()));

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

        // Initiators
        chkAllInitiators.setSelected(extension.isInitiatorsAll());
        var selectedCsv = extension.getInitiatorsSelectedCsv();
        var selectedIds = parseCsv(selectedCsv);
        initiatorBoxes.forEach((id, cb) -> cb.setSelected(selectedIds.contains(id)));
        setInitiatorBoxesEnabled(!chkAllInitiators.isSelected());
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

        // Initiators
        extension.setInitiatorsAll(chkAllInitiators.isSelected());
        if (chkAllInitiators.isSelected()) {
            // Clear explicit list; All means allow everything including future ones
            extension.setInitiatorsSelectedCsv("");
        } else {
            List<Integer> ids = new ArrayList<>();
            initiatorBoxes.forEach((id, cb) -> { if (cb.isSelected()) ids.add(id); });
            extension.setInitiatorsSelectedCsv(joinCsv(ids));
        }
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

    private void buildInitiatorCheckboxes() {
        // Discover initiator constants dynamically from HttpSender
        Map<Integer, String> discovered = new LinkedHashMap<>();
        for (Field f : org.parosproxy.paros.network.HttpSender.class.getFields()) {
            if (!Modifier.isStatic(f.getModifiers()) || !Modifier.isFinal(f.getModifiers())) continue;
            if (f.getType() != int.class) continue;
            String name = f.getName();
            // ZAP constants end with _INITIATOR (e.g., ACTIVE_SCANNER_INITIATOR)
            if (!name.endsWith("_INITIATOR")) continue;
            // Exclude certain initiators from the UI list
            if ("CHECK_FOR_UPDATES_INITIATOR".equals(name)
                    || "PARAM_DIGGER_INITIATOR".equals(name)
                    || "TOKEN_GENERATOR_INITIATOR".equals(name)) {
                continue;
            }
            try {
                int id = f.getInt(null);
                String base = name.substring(0, name.length() - "_INITIATOR".length());
                discovered.put(id, prettyInitiatorLabel(base));
            } catch (IllegalAccessException ignored) {
            }
        }

        // Render as a grid, 2 columns
        GridBagConstraints g = new GridBagConstraints();
        g.gridx = g.gridy = 0;
        g.anchor = GridBagConstraints.WEST;
        g.insets = new Insets(2, 12, 2, 6);
        int col = 0;
        for (Map.Entry<Integer, String> e : discovered.entrySet()) {
            JCheckBox cb = new JCheckBox(e.getValue());
            initiatorBoxes.put(e.getKey(), cb);
            initiatorsPanel.add(cb, g);
            col++;
            if (col == 2) { col = 0; g.gridx = 0; g.gridy++; } else { g.gridx++; }
        }
    }

    private void setInitiatorBoxesEnabled(boolean enabled) {
        initiatorBoxes.values().forEach(cb -> cb.setEnabled(enabled));
    }

    private static String prettyInitiatorLabel(String raw) {
        // e.g., ACTIVE_SCANNER -> Active Scanner
        String[] parts = raw.split("_");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            String p = parts[i].toLowerCase();
            if (p.isEmpty()) continue;
            sb.append(Character.toUpperCase(p.charAt(0))).append(p.substring(1));
            if (i < parts.length - 1) sb.append(' ');
        }
        return sb.toString();
    }

    private static List<Integer> parseCsv(String csv) {
        List<Integer> list = new ArrayList<>();
        if (csv == null || csv.isEmpty()) return list;
        for (String s : csv.split(",")) {
            try { list.add(Integer.parseInt(s.trim())); } catch (Exception ignored) {}
        }
        return list;
    }

    private static String joinCsv(List<Integer> list) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(list.get(i));
        }
        return sb.toString();
    }
}
