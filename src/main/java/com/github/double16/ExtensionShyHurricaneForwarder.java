package com.github.double16;

import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;

import java.net.URL;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.alert.AlertEventPublisher;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.network.HttpSenderListener;

@SuppressWarnings("unused")
public class ExtensionShyHurricaneForwarder extends ExtensionAdaptor implements EventConsumer, Runnable, HttpSenderListener {

    private static final String NAME = "ShyHurricane Forwarder";
    private static final String INDEX_PATH = "/index";
    private static final String FINDINGS_PATH = "/findings";


    /**
     * Prefixes that should always be skipped.
     */
    private static final String[] SKIP_PREFIXES = {
            "audio/",
            "video/",
            "font/",
            "binary/"
    };

    /**
     * Exact content-types that should be skipped.
     */
    private static final Set<String> SKIP_TYPES = Set.of(
            "application/octet-stream",
            "application/pdf",
            "application/x-pdf",
            "application/zip",
            "application/x-zip-compressed",
            "application/x-protobuf",
            "application/font-woff",
            "application/font-woff2",
            "application/vnd.ms-fontobject"
    );

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Maps alert fingerprint to time millis when recorded. Prevents repeating alerts. The time is so we can clean up the map.
     */
    private final ConcurrentHashMap<String, Long> processedFingerprints = new ConcurrentHashMap<>();
    /**
     * Holds the list of pending alerts to post.
     */
    private final ConcurrentLinkedQueue<String> pendingAlerts = new ConcurrentLinkedQueue<>();
    /**
     * The alert event does not have all of the information we want. We can't query for a single Alert, only all alerts.
     * So, we collect the alert IDs we want and periodically query all alerts and POST the findings.
     */
    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

    // TODO: config items:
    private final boolean onlyInScope = true;
    private final String mcpServerUrl = "http://localhost:8000";
    private final int minimumConfidenceLevel = Alert.CONFIDENCE_MEDIUM;
    private final int minimumRiskLevel = Alert.RISK_INFO;

    @SuppressWarnings("unused")
    public ExtensionShyHurricaneForwarder() {
        super(NAME);
    }

    @Override
    public boolean supportsLowMemory() {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        ZAP.getEventBus().registerConsumer(this, AlertEventPublisher.getPublisher().getPublisherName(), AlertEventPublisher.ALERT_ADDED_EVENT);
        executor.scheduleWithFixedDelay(this, 60, 120, TimeUnit.SECONDS);

        extensionHook.addHttpSenderListener(this);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        ZAP.getEventBus().unregisterConsumer(this);
        executor.shutdown();
        pendingAlerts.clear();
        processedFingerprints.clear();

        // ZAP handles removing the HttpSenderListener

        super.unload();
    }

    @Override
    public void eventReceived(Event event) {
        Map<String, String> map = event.getParameters();
        int confidence = Integer.parseInt(map.get(AlertEventPublisher.CONFIDENCE));
        if (confidence < minimumConfidenceLevel) {
            return;
        }
        int risk = Integer.parseInt(map.get(AlertEventPublisher.RISK));
        if (risk < minimumRiskLevel) {
            return;
        }
        String fingerprint = alertFingerprint(event);
        if (processedFingerprints.containsKey(fingerprint)) {
            return;
        }
        processedFingerprints.putIfAbsent(fingerprint, System.currentTimeMillis());
        pendingAlerts.offer(map.get(AlertEventPublisher.ALERT_ID));
    }

    @Override
    public void run() {
        ExtensionAlert exAlert = null;
        Map<Integer, Alert> allAlerts = null;

        String alertId;
        while ((alertId = pendingAlerts.poll()) != null) {
            if (exAlert == null) {
                exAlert = (ExtensionAlert) org.parosproxy.paros.control.Control.getSingleton().
                        getExtensionLoader().getExtension(
                                ExtensionAlert.NAME);
                allAlerts = new HashMap<>();
                for (Alert alert : exAlert.getAllAlerts()) {
                    allAlerts.put(alert.getAlertId(), alert);
                }
            }

            Alert alert = allAlerts.get(Integer.parseInt(alertId));
            if (alert == null) {
                continue;
            }
            if (onlyInScope) {
                if (alert.getMessage() != null && !alert.getMessage().isInScope()) {
                    continue;
                }
            }

            try {
                String title = alert.getName() + " at " + alert.getUri();
                StringBuilder markdown = new StringBuilder();
                markdown.append("# ").append(title).append("\n\n");
                markdown.append(String.format("""
                        **Summary**
                        %s
                        Risk: %s
                        Confidence: %s
                        """, alert.getDescription(), Alert.MSG_RISK[alert.getRisk()], Alert.MSG_CONFIDENCE[alert.getConfidence()]));
                if (StringUtils.isNotBlank(alert.getOtherInfo())) {
                    markdown.append(alert.getOtherInfo()).append("\n");
                }
                markdown.append(String.format("\n**Discovery Method**\nDiscovered by OWASP ZAP (Plugin ID: %d)\n", alert.getPluginId()));
                if (StringUtils.isNotBlank(alert.getEvidence())) {
                    markdown.append(String.format("Evidence: `%s`\n", alert.getEvidence()));
                }
                markdown.append(String.format("\n**Reproduction Steps**\nAccess the following URL: `%s %s`\n",
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
                if (alert.getCweId() > 0 || alert.getWascId() > 0 || StringUtils.isNotBlank(alert.getReference())) {
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
                postFinding(alert.getUri(), title, markdown.toString());

            } catch (Exception e) {
                System.err.println("[ShyHurricaneForwarder] Error posting finding: " + e.getMessage());
            }
        }

    }

    private void postFinding(String target, String title, String markdown) throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("target", target);
        data.put("title", title);
        data.put("markdown", markdown);
        postData(mcpServerUrl + FINDINGS_PATH, data);
    }

    private String alertFingerprint(Event alertEvent) {
        Map<String, String> map = alertEvent.getParameters();
        return map.get(AlertEventPublisher.PLUGIN_ID)
                + "/"
                + map.get(AlertEventPublisher.NAME)
                + "/"
                + map.get(AlertEventPublisher.RISK)
                + "/"
                + map.get(AlertEventPublisher.CONFIDENCE);
    }

    @Override
    public int getListenerOrder() {
        return 1000;
    }

    private boolean shouldSkip(String contentType) {
        if (contentType == null || contentType.isEmpty()) {
            return false;
        }

        String ct = contentType.toLowerCase();

        // Pass through JSON/XML subtypes (e.g., "application/vnd.api+json")
        if (ct.contains("+json") || ct.contains("+xml")) {
            return false;
        }

        // Skip if it matches one of the configured prefixes
        for (String prefix : SKIP_PREFIXES) {
            if (ct.startsWith(prefix)) {
                return true;
            }
        }

        // Skip non-SVG images
        if (ct.startsWith("image/") && !ct.contains("svg")) {
            return true;
        }

        // Skip any explicitly listed types
        return SKIP_TYPES.contains(ct);
    }

    /**
     * Katana headers are lowercase with underscores.
     */
    private Map<String, String> toKatanaHeaders(HttpHeader headers) {
        Map<String, String> map = new HashMap<>();
        for (HttpHeaderField header : headers.getHeaders()) {
            String katanaHeaderName = header.getName().toLowerCase().replace('-', '_');
            if (map.containsKey(header.getName())) {
                map.put(katanaHeaderName, map.get(katanaHeaderName) + ";" + header.getValue());
            } else {
                map.put(katanaHeaderName, header.getValue());
            }
        }
        return map;
    }

    @Override
    public void onHttpRequestSend(HttpMessage msg, int initiator, HttpSender sender) {
        if (onlyInScope && !msg.isInScope()) {
            return;
        }

        HttpRequestHeader req_hdr = msg.getRequestHeader();
        HttpResponseHeader res_hdr = msg.getResponseHeader();

        String contentType = res_hdr.getNormalisedContentTypeValue();
        if (shouldSkip(contentType)) {
            return;
        }

        String now = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        Map<String, Object> request = new HashMap<>();
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> entry = new HashMap<>();
        entry.put("timestamp", now);
        entry.put("request", request);
        entry.put("response", response);

        request.put("method", req_hdr.getMethod());
        request.put("endpoint", req_hdr.getURI().toString());
        request.put("headers", toKatanaHeaders(req_hdr));
        try {
            request.put("body", msg.getRequestBody().toString());
        } catch (Exception e) {
            // bad unicode chars or binary data
        }

        response.put("status_code", res_hdr.getStatusCode());
        response.put("headers", toKatanaHeaders(res_hdr));
        try {
            response.put("body", msg.getResponseBody().toString());
        } catch (Exception e) {
            // bad unicode chars or binary data
        }
        response.put("rtt", msg.getTimeElapsedMillis() / 1000.0);

        try {
            postIndex(entry);
        } catch (Exception e) {
            System.err.println("[ShyHurricaneForwarder] Error posting index: " + e.getMessage());
        }
    }

    private void postIndex(Map<String, Object> data) throws Exception {
        postData(mcpServerUrl + INDEX_PATH, data);
    }

    private void postData(String urlStr, Map<String, Object> data) throws Exception {
        String jsonBody = MAPPER.writeValueAsString(data);

        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        try (var writer = new OutputStreamWriter(conn.getOutputStream())) {
            writer.write(jsonBody);
        }

        int status = conn.getResponseCode();
        if (status >= 400) {
            System.err.println("[ShyHurricaneForwarder] Failed to POST " + urlStr + ": HTTP " + status);
        }
    }

    @Override
    public void onHttpResponseReceive(HttpMessage msg, int initiator, HttpSender sender) {
        // do nothing
    }
}
