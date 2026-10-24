package com.github.double16;

import static com.github.double16.ForwardingTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.swing.SwingUtilities;
import org.apache.commons.configuration.XMLConfiguration;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookMenu;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.OutputPanel;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.extension.alert.AlertEventPublisher;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.view.messagecontainer.http.SingleHttpMessageContainer;

class ExtensionShyHurricaneForwarderLifecycleTest {
    @org.junit.jupiter.api.BeforeAll
    static void initializeMessages() {
        if (org.parosproxy.paros.Constant.messages == null) {
            org.parosproxy.paros.Constant.messages =
                    new org.zaproxy.zap.utils.I18N(java.util.Locale.ENGLISH);
        }
    }

    private static TestExtension configuredExtension() {
        final var parameters = new ShyHurricaneOptionsParam();
        parameters.load(new XMLConfiguration());
        return new TestExtension(parameters);
    }

    @Test
    void hooksHeadlessWithoutCreatingMenusAndCanUnload() {
        final var extension = configuredExtension();
        final var hook = spy(new ExtensionHook(null, null));
        try {
            extension.hook(hook);
            assertTrue(extension.canUnload());
            assertTrue(hook.getOptionsParamSetList().size() > 0);
            verify(hook, never()).getHookView();
            verify(hook, never()).getHookMenu();
        } finally {
            extension.unload();
        }
    }

    @Test
    @Disabled
    void guiMenusBypassAllFiltersAndReportOnEdt() throws Exception {
        try (final var support = new ForwardingTestSupport()) {
            final var extension = configuredExtension();
            final ViewDelegate view = mock(ViewDelegate.class);
            final OutputPanel output = mock(OutputPanel.class);
            final CountDownLatch reported = new CountDownLatch(1);
            when(view.getOutputPanel()).thenReturn(output);
            doAnswer(
                            invocation -> {
                                assertTrue(SwingUtilities.isEventDispatchThread());
                                reported.countDown();
                                return null;
                            })
                    .when(output)
                    .append(anyString());
            final ExtensionHook hook = spy(new ExtensionHook(null, view));
            final ExtensionHookMenu menuHook = mock(ExtensionHookMenu.class);
            doReturn(menuHook).when(hook).getHookMenu();
            extension.initView(view);
            extension.setMcpServerUrl(support.url());
            extension.setOnlyInScope(true);
            extension.setMinimumRiskLevel(Alert.RISK_HIGH);
            extension.setMinimumConfidenceLevel(Alert.CONFIDENCE_USER_CONFIRMED);
            extension.setInitiatorsAll(false);
            extension.setInitiatorsSelectedCsv("");
            for (int group = 2; group <= 5; group++) extension.setStatusGroupSelected(group, false);
            try {
                SwingUtilities.invokeAndWait(() -> extension.hook(hook));
                final var captor =
                        org.mockito.ArgumentCaptor.forClass(ExtensionPopupMenuItem.class);
                verify(menuHook, times(2)).addPopupMenuItem(captor.capture());
                final var menu = (ShyHurricaneMenus.Messages) captor.getAllValues().get(1);
                final var container = mock(SingleHttpMessageContainer.class);
                when(container.getName()).thenReturn("Response viewer");
                when(container.getMessage()).thenReturn(message());
                SwingUtilities.invokeAndWait(
                        () -> {
                            assertTrue(menu.isEnableForMessageContainer(container));
                            assertTrue(menu.isEnabled());
                            menu.doClick(0);
                        });
                assertTrue(reported.await(5, TimeUnit.SECONDS));
                verify(output).append(contains("1 HTTP exchanges"));
                verify(view, never()).showWarningDialog(anyString());
                assertEquals(1, support.deliveries.size());

                final CountDownLatch warned = new CountDownLatch(1);
                doAnswer(
                                invocation -> {
                                    assertTrue(SwingUtilities.isEventDispatchThread());
                                    warned.countDown();
                                    return null;
                                })
                        .when(view)
                        .showWarningDialog(anyString());
                extension.reportManualSend("partial", true);
                assertTrue(warned.await(5, TimeUnit.SECONDS));
            } finally {
                extension.unload();
            }
            extension.initView(null);
            extension.reportManualSend("no view", true);
            SwingUtilities.invokeAndWait(() -> {});
        }
    }

    @Test
    void settingsDelegatesKeepExistingOptions() {
        final var extension = configuredExtension();
        try {
            extension.setOnlyInScope(false);
            assertFalse(extension.isOnlyInScope());
            extension.setMcpServerUrl("http://localhost:1234");
            assertEquals("http://localhost:1234", extension.getMcpServerUrl());
            extension.setMinimumRiskLevel(2);
            extension.setMinimumConfidenceLevel(3);
            assertEquals(2, extension.getMinimumRiskLevel());
            assertEquals(3, extension.getMinimumConfidenceLevel());
            extension.setInitiatorsAll(false);
            extension.setInitiatorsSelectedCsv("1,2");
            assertFalse(extension.isInitiatorsAll());
            assertEquals("1,2", extension.getInitiatorsSelectedCsv());
            extension.setStatusGroupSelected(3, true);
            assertTrue(extension.isStatusGroupSelected(3));
            extension.onHttpRequestSend(null, 0, null);
        } finally {
            extension.unload();
        }
    }

    @Test
    void automaticAlertsRespectThresholdsScopeAndFingerprintSuppression() throws Exception {
        try (final var support = new ForwardingTestSupport()) {
            final ExtensionLoader loader = mock(ExtensionLoader.class);
            final ExtensionAlert alertExtension = mock(ExtensionAlert.class);
            when(loader.getExtension(ExtensionAlert.NAME)).thenReturn(alertExtension);
            Control.initSingletonForTesting(null, loader);
            final var extension = configuredExtension();
            extension.setMcpServerUrl(support.url());
            extension.setOnlyInScope(true);
            final HttpMessage outside = spy(message());
            doReturn(false).when(outside).isInScope();
            final HttpMessage inside = spy(message());
            doReturn(true).when(inside).isInScope();
            final List<Alert> alerts = List.of(alert(1, outside), alert(2, inside), alert(3, null));
            when(alertExtension.getAllAlerts()).thenReturn(alerts);
            try {
                extension.setMinimumRiskLevel(2);
                extension.setMinimumConfidenceLevel(2);
                extension.eventReceived(event(1, 1, 3));
                extension.eventReceived(event(1, 3, 1));
                extension.run();
                verify(alertExtension, never()).getAllAlerts();
                extension.setMinimumRiskLevel(0);
                extension.setMinimumConfidenceLevel(0);
                for (int id = 1; id <= 4; id++) extension.eventReceived(event(id, 0, 0));
                extension.eventReceived(event(2, 0, 0));
                extension.run();
                assertEquals(
                        2,
                        support.deliveries.size(),
                        "Outside-scope and missing alerts are skipped");
                verify(alertExtension, times(1)).getAllAlerts();
                support.sender.sendAlerts(List.of(alerts.get(1)));
                assertTrue(support.completed().text().contains("1 findings and 1 HTTP exchanges"));
                extension.eventReceived(event(2, 0, 0));
                extension.run();
                assertEquals(
                        4,
                        support.deliveries.size(),
                        "Manual sends bypass but do not reset automatic fingerprints");
                extension.setOnlyInScope(false);
                support.findingsStatus = 500;
                extension.eventReceived(event(1, 1, 1));
                extension.run();
                assertEquals(5, support.deliveries.size());
            } finally {
                extension.unload();
            }
        }
    }

    @Test
    void automaticHttpStillRespectsScopeAndInitiatorsAndHandlesNetworkErrors() throws Exception {
        try (final var support = new ForwardingTestSupport()) {
            final var parameters = new ShyHurricaneOptionsParam();
            parameters.load(new XMLConfiguration());
            final var extension = new ExtensionShyHurricaneForwarder(parameters);
            extension.setMcpServerUrl(support.url());
            extension.setOnlyInScope(true);
            extension.setStatusGroupSelected(4, true);
            final HttpMessage traffic = spy(message());
            doReturn(false).when(traffic).isInScope();
            try {
                extension.onHttpResponseReceive(traffic, 1, null);
                assertTrue(support.deliveries.isEmpty());
                doReturn(true).when(traffic).isInScope();
                traffic.getResponseHeader().setHeader("Content-Type", "application/json");
                extension.setInitiatorsAll(false);
                extension.setInitiatorsSelectedCsv("1");
                extension.onHttpResponseReceive(traffic, 1, null);
                assertEquals(1, support.deliveries.size());
                support.indexStatus = 500;
                extension.onHttpResponseReceive(traffic, 1, null);
                assertEquals(2, support.deliveries.size());
            } finally {
                extension.unload();
            }
        }
    }

    private static final class TestExtension extends ExtensionShyHurricaneForwarder {
        private ViewDelegate testView;

        TestExtension(final ShyHurricaneOptionsParam parameters) {
            super(parameters);
        }

        @Override
        public void initView(final ViewDelegate view) {
            testView = view;
        }

        @Override
        public ViewDelegate getView() {
            return testView;
        }

        @Override
        protected boolean hasView() {
            return testView != null;
        }
    }

    private static Event event(final int id, final int risk, final int confidence) {
        final Map<String, String> parameters = new HashMap<>();
        parameters.put(AlertEventPublisher.ALERT_ID, Integer.toString(id));
        parameters.put(AlertEventPublisher.PLUGIN_ID, Integer.toString(id));
        parameters.put(AlertEventPublisher.NAME, "Alert " + id);
        parameters.put(AlertEventPublisher.RISK, Integer.toString(risk));
        parameters.put(AlertEventPublisher.CONFIDENCE, Integer.toString(confidence));
        return new Event(null, "test", null, parameters);
    }
}
