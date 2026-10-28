package com.github.double16;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;

/** Payloads shared by automatic forwarding and explicit selections. */
final class ForwardingPayloads {
    private static final Map<Integer, String> CWE_CATEGORIES =
            Map.of(79, "xss", 78, "injection", 89, "injection", 918, "ssrf");

    private ForwardingPayloads() {}

    static Map<String, Object> finding(final Alert alert) {
        final String title = alert.getName() + " at " + alert.getUri();
        final StringBuilder markdown = new StringBuilder();
        markdown.append("# ").append(title).append("\n\n");
        markdown.append(
                String.format(
                        """
                **Summary**
                %s
                Risk: %s
                Confidence: %s
                """,
                        alert.getDescription(),
                        label(Alert.MSG_RISK, alert.getRisk()),
                        label(Alert.MSG_CONFIDENCE, alert.getConfidence())));
        if (StringUtils.isNotBlank(alert.getOtherInfo())) {
            markdown.append(alert.getOtherInfo()).append("\n");
        }
        markdown.append(
                String.format(
                        "\n**Discovery Method**\nDiscovered by OWASP ZAP (Plugin ID: %d)\n",
                        alert.getPluginId()));
        if (StringUtils.isNotBlank(alert.getEvidence())) {
            markdown.append(String.format("Evidence: `%s`\n", alert.getEvidence()));
        }
        markdown.append(
                String.format(
                        "\n**Reproduction Steps**\nAccess the following URL: `%s %s`\n",
                        StringUtils.isNotBlank(alert.getMethod()) ? alert.getMethod() : "GET",
                        alert.getUri()));
        if (StringUtils.isNotBlank(alert.getParam())) {
            markdown.append(String.format("Parameter: `%s`\n", alert.getParam()));
        }
        if (StringUtils.isNotBlank(alert.getPostData())) {
            markdown.append(String.format("Data: `%s`\n", alert.getPostData()));
        }
        if (StringUtils.isNotBlank(alert.getInputVector())) {
            markdown.append(String.format("Input vector: `%s`\n", alert.getInputVector()));
        }
        if (StringUtils.isNotBlank(alert.getAttack())) {
            markdown.append(String.format("Attack: `%s`\n", alert.getAttack()));
        }
        if (StringUtils.isNotBlank(alert.getSolution())) {
            markdown.append(String.format("\n**Solution**\n%s\n", alert.getSolution()));
        }
        if (alert.getCweId() > 0
                || alert.getWascId() > 0
                || StringUtils.isNotBlank(alert.getReference())) {
            markdown.append("\n**References**\n");
            if (alert.getCweId() > 0) {
                markdown.append(String.format("- CWE-%d\n", alert.getCweId()));
            }
            if (alert.getWascId() > 0) {
                markdown.append(String.format("- WASC-%d\n", alert.getWascId()));
            }
            if (StringUtils.isNotBlank(alert.getReference())) {
                markdown.append("- ").append(alert.getReference().replace("\n", "\n- "));
            }
        }
        return Map.of(
                "target",
                alert.getUri(),
                "title",
                title,
                "markdown",
                markdown.toString(),
                "metadata",
                metadata(alert));
    }

    private static String label(final String[] labels, final int value) {
        return value >= 0 && value < labels.length ? labels[value] : null;
    }

    private static Map<String, Object> metadata(final Alert alert) {
        final Map<String, Object> metadata = new HashMap<>();
        metadata.put("source", "zap");
        metadata.put("rule_id", Integer.toString(alert.getPluginId()));
        if (alert.getAlertId() >= 0) {
            metadata.put("source_finding_id", Integer.toString(alert.getAlertId()));
        }
        metadata.put(
                "severity",
                switch (alert.getRisk()) {
                    case Alert.RISK_INFO -> "informational";
                    case Alert.RISK_LOW -> "low";
                    case Alert.RISK_MEDIUM -> "medium";
                    case Alert.RISK_HIGH -> "high";
                    default -> "unknown";
                });
        final boolean falsePositive = alert.getConfidence() == Alert.CONFIDENCE_FALSE_POSITIVE;
        metadata.put("verification_status", falsePositive ? "false_positive" : "unverified");
        if (!falsePositive) {
            metadata.put(
                    "confidence",
                    switch (alert.getConfidence()) {
                        case Alert.CONFIDENCE_LOW -> "low";
                        case Alert.CONFIDENCE_MEDIUM -> "medium";
                        case Alert.CONFIDENCE_HIGH, Alert.CONFIDENCE_USER_CONFIRMED -> "high";
                        default -> "unknown";
                    });
        }
        final String nativeSeverity = label(Alert.MSG_RISK, alert.getRisk());
        final String nativeConfidence = label(Alert.MSG_CONFIDENCE, alert.getConfidence());
        if (nativeSeverity != null) metadata.put("native_severity", nativeSeverity);
        if (nativeConfidence != null) metadata.put("native_confidence", nativeConfidence);
        final HttpMessage message = alert.getMessage();
        if (message != null) {
            final String method = message.getRequestHeader().getMethod();
            if (StringUtils.isNotBlank(method)) {
                metadata.put("affected_method", method.toUpperCase(Locale.ROOT));
            }
        }
        if (alert.getCweId() > 0) metadata.put("cwe_ids", List.of("CWE-" + alert.getCweId()));
        final String category = CWE_CATEGORIES.get(alert.getCweId());
        if (category != null) metadata.put("vulnerability_types", List.of(category));
        if (StringUtils.isNotBlank(alert.getParam())) {
            metadata.put("parameter", Map.of("name", alert.getParam()));
        }
        return Map.copyOf(metadata);
    }

    static Map<String, String> headers(final HttpHeader headers) {
        final Map<String, String> map = new HashMap<>();
        for (final HttpHeaderField header : headers.getHeaders()) {
            final String katanaHeaderName = header.getName().toLowerCase(Locale.ROOT);
            if (map.containsKey(katanaHeaderName)) {
                map.put(katanaHeaderName, map.get(katanaHeaderName) + ";" + header.getValue());
            } else {
                map.put(katanaHeaderName, header.getValue());
            }
        }
        return map;
    }

    static Map<String, Object> index(final HttpMessage msg) {
        final HttpRequestHeader requestHeader = msg.getRequestHeader();
        final HttpResponseHeader responseHeader = msg.getResponseHeader();
        final String now = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        final Map<String, Object> request = new HashMap<>();
        final Map<String, Object> response = new HashMap<>();
        final Map<String, Object> entry = new HashMap<>();
        entry.put("timestamp", now);
        entry.put("request", request);
        entry.put("response", response);

        request.put("method", requestHeader.getMethod());
        request.put("endpoint", requestHeader.getURI().toString());
        request.put("headers", headers(requestHeader));
        try {
            request.put("body", msg.getRequestBody().toString());
        } catch (Exception e) {
            // bad unicode chars or binary data
        }

        response.put("status_code", responseHeader.getStatusCode());
        response.put("headers", headers(responseHeader));
        try {
            response.put("body", msg.getResponseBody().toString());
        } catch (Exception e) {
            // bad unicode chars or binary data
        }
        response.put("rtt", msg.getTimeElapsedMillis() / 1000.0);

        return entry;
    }
}
