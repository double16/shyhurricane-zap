package com.github.double16;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.alert.AlertEventPublisher;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.network.HttpSenderListener;

@SuppressWarnings("unused")
public class ExtensionShyHurricaneForwarder extends ExtensionAdaptor
        implements EventConsumer, Runnable, HttpSenderListener {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionShyHurricaneForwarder.class);
    private static final String NAME = "ShyHurricane";
    private static final String INDEX_PATH = "/index";
    private static final String FINDINGS_PATH = "/findings";

    /** Prefixes that should always be skipped. */
    private static final String[] SKIP_PREFIXES = {"audio/", "video/", "font/", "binary/"};

    /** Exact content-types that should be skipped. */
    private static final Set<String> SKIP_TYPES =
            Set.of(
                    "application/octet-stream",
                    "application/pdf",
                    "application/x-pdf",
                    "application/zip",
                    "application/x-zip-compressed",
                    "application/x-protobuf",
                    "application/font-woff",
                    "application/font-woff2",
                    "application/vnd.ms-fontobject");

    /**
     * Maps alert fingerprint to time millis when recorded. Prevents repeating alerts. The time is
     * so we can clean up the map.
     */
    private final ConcurrentHashMap<AlertFingerprint, Long> processedFingerprints =
            new ConcurrentHashMap<>();

    /** Holds the list of pending alerts to post. */
    private final ConcurrentLinkedQueue<String> pendingAlerts = new ConcurrentLinkedQueue<>();

    /**
     * The alert event does not have all of the information we want. We can't query for a single
     * Alert, only all alerts. So, we collect the alert IDs we want and periodically query all
     * alerts and POST the findings.
     */
    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

    private final ShyHurricaneOptionsParam param;
    private final ManualSendService manualSender =
            new ManualSendService(() -> getMcpServerUrl(), this::reportManualSend);

    void reportManualSend(final String summary, final boolean warning) {
        javax.swing.SwingUtilities.invokeLater(
                () -> {
                    if (hasView()) {
                        getView().getOutputPanel().append("[ShyHurricane] " + summary + "\n");
                        if (warning) {
                            getView().showWarningDialog(summary);
                        }
                    }
                });
    }

    @SuppressWarnings("unused")
    public ExtensionShyHurricaneForwarder() {
        this(new ShyHurricaneOptionsParam());
    }

    ExtensionShyHurricaneForwarder(ShyHurricaneOptionsParam param) {
        super(NAME);
        this.param = Objects.requireNonNull(param);
    }

    boolean isStatusGroupSelected(int group) {
        return param.isStatusGroupSelected(group);
    }

    void setStatusGroupSelected(int group, boolean selected) {
        param.setStatusGroupSelected(group, selected);
    }

    boolean isOnlyInScope() {
        return param.isOnlyInScope();
    }

    String getMcpServerUrl() {
        return param.getMcpServerUrl();
    }

    int getMinimumConfidenceLevel() {
        return param.getMinConfidenceLevel();
    }

    int getMinimumRiskLevel() {
        return param.getMinRiskLevel();
    }

    boolean isInitiatorsAll() {
        return param.isInitiatorsAll();
    }

    void setInitiatorsAll(boolean v) {
        param.setInitiatorsAll(v);
    }

    String getInitiatorsSelectedCsv() {
        return param.getInitiatorsSelectedCsv();
    }

    void setInitiatorsSelectedCsv(String csv) {
        param.setInitiatorsSelectedCsv(csv);
    }

    void setOnlyInScope(boolean v) {
        param.setOnlyInScope(v);
    }

    void setMcpServerUrl(String v) {
        param.setMcpServerUrl(v);
    }

    void setMinimumConfidenceLevel(int v) {
        param.setMinConfidenceLevel(v);
    }

    void setMinimumRiskLevel(int v) {
        param.setMinRiskLevel(v);
    }

    private String getMcpServerPath(String path) {
        StringBuilder sb = new StringBuilder(getMcpServerUrl());
        if (sb.charAt(sb.length() - 1) != '/') {
            sb.append('/');
        }
        if (path.startsWith("/")) {
            path = path.substring(1);
        }
        sb.append(path);
        return sb.toString();
    }

    @Override
    public boolean supportsLowMemory() {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addOptionsParamSet(param);

        ZAP.getEventBus()
                .registerConsumer(
                        this,
                        AlertEventPublisher.getPublisher().getPublisherName(),
                        AlertEventPublisher.ALERT_ADDED_EVENT);
        executor.scheduleWithFixedDelay(this, 60, 120, TimeUnit.SECONDS);

        extensionHook.addHttpSenderListener(this);

        if (hasView()) {
            extensionHook.getHookView().addOptionPanel(new ShyHurricaneOptionsPanel(this));
            ShyHurricaneMenus.register(extensionHook.getHookMenu(), manualSender);
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        ZAP.getEventBus().unregisterConsumer(this);
        executor.shutdownNow();
        manualSender.close();
        pendingAlerts.clear();
        processedFingerprints.clear();

        // ZAP handles removing the HttpSenderListener

        super.unload();
    }

    @Override
    public void eventReceived(Event event) {
        Map<String, String> map = event.getParameters();
        int confidence = Integer.parseInt(map.get(AlertEventPublisher.CONFIDENCE));
        if (confidence < getMinimumConfidenceLevel()) {
            return;
        }
        int risk = Integer.parseInt(map.get(AlertEventPublisher.RISK));
        if (risk < getMinimumRiskLevel()) {
            return;
        }
        final AlertFingerprint fingerprint = alertFingerprint(event);
        if (processedFingerprints.putIfAbsent(fingerprint, System.currentTimeMillis()) != null) {
            return;
        }
        pendingAlerts.offer(map.get(AlertEventPublisher.ALERT_ID));
    }

    @Override
    public void run() {
        ExtensionAlert exAlert = null;
        Map<Integer, Alert> allAlerts = null;

        String alertId;
        while ((alertId = pendingAlerts.poll()) != null) {
            if (exAlert == null) {
                exAlert =
                        (ExtensionAlert)
                                org.parosproxy.paros.control.Control.getSingleton()
                                        .getExtensionLoader()
                                        .getExtension(ExtensionAlert.NAME);
                allAlerts = new HashMap<>();
                for (Alert alert : exAlert.getAllAlerts()) {
                    allAlerts.put(alert.getAlertId(), alert);
                }
            }

            Alert alert = allAlerts.get(Integer.parseInt(alertId));
            if (alert == null) {
                continue;
            }
            if (isOnlyInScope()) {
                if (alert.getMessage() != null && !alert.getMessage().isInScope()) {
                    continue;
                }
            }

            try {
                postData(getMcpServerPath(FINDINGS_PATH), ForwardingPayloads.finding(alert));

            } catch (Exception e) {
                LOGGER.warn("Error posting finding ({})", e.getClass().getSimpleName());
            }
        }
    }

    private record AlertFingerprint(
            String pluginId,
            String name,
            String risk,
            String confidence,
            String alertId,
            String uri,
            String parameter) {}

    private AlertFingerprint alertFingerprint(final Event alertEvent) {
        final Map<String, String> map = alertEvent.getParameters();
        return new AlertFingerprint(
                map.get(AlertEventPublisher.PLUGIN_ID),
                map.get(AlertEventPublisher.NAME),
                map.get(AlertEventPublisher.RISK),
                map.get(AlertEventPublisher.CONFIDENCE),
                map.get(AlertEventPublisher.ALERT_ID),
                map.get(AlertEventPublisher.URI),
                map.get(AlertEventPublisher.PARAM));
    }

    @Override
    public int getListenerOrder() {
        return 1000;
    }

    private boolean shouldSkip(String contentType) {
        if (contentType == null || contentType.isEmpty()) {
            return false;
        }

        String ct = contentType.toLowerCase(Locale.ROOT);

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

    /** Katana headers are lowercase with underscores. */
    private Map<String, String> toKatanaHeaders(HttpHeader headers) {
        return ForwardingPayloads.headers(headers);
    }

    @Override
    public void onHttpResponseReceive(HttpMessage msg, int initiator, HttpSender sender) {
        // Filter by request initiator if configured
        if (!param.isInitiatorsAll() && !param.isInitiatorSelected(initiator)) {
            return;
        }
        if (isOnlyInScope() && !msg.isInScope()) {
            return;
        }

        HttpResponseHeader res_hdr = msg.getResponseHeader();

        if (!param.isStatusCodeSelected(res_hdr.getStatusCode())) {
            return;
        }

        String contentType = res_hdr.getNormalisedContentTypeValue();
        if (shouldSkip(contentType)) {
            return;
        }

        try {
            postData(getMcpServerPath(INDEX_PATH), ForwardingPayloads.index(msg));
        } catch (Exception e) {
            LOGGER.warn("Error posting index ({})", e.getClass().getSimpleName());
        }
    }

    private void postData(String urlStr, Map<String, Object> data) throws Exception {
        ShyHurricaneClient.post(urlStr, data);
    }

    @Override
    public void onHttpRequestSend(HttpMessage msg, int initiator, HttpSender sender) {
        // do nothing
    }
}
