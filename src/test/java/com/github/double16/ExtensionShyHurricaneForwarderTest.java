package com.github.double16;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.Queue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.extension.alert.AlertEventPublisher;

class ExtensionShyHurricaneForwarderTest {

    private ExtensionShyHurricaneForwarder ext;

    @BeforeEach
    void setUp() {
        ext = new ExtensionShyHurricaneForwarder();
    }

    @Test
    void supportsLowMemory_isTrue() {
        assertTrue(ext.supportsLowMemory());
    }

    @Test
    void listenerOrder_isStable() {
        assertEquals(1000, ext.getListenerOrder());
    }

    @Test
    void onlyInScope_flagToggles() {
        // Inject a param stub that controls onlyInScope
        ext =
                new ExtensionShyHurricaneForwarder(
                        new ShyHurricaneOptionsParam() {
                            @Override
                            public boolean isOnlyInScope() {
                                return false;
                            }
                        });
        assertFalse(ext.isOnlyInScope());

        ext =
                new ExtensionShyHurricaneForwarder(
                        new ShyHurricaneOptionsParam() {
                            @Override
                            public boolean isOnlyInScope() {
                                return true;
                            }
                        });
        assertTrue(ext.isOnlyInScope());
    }

    @Test
    void getMcpServerPath_joinsWithSingleSlash() throws Exception {
        ext =
                new ExtensionShyHurricaneForwarder(
                        new ShyHurricaneOptionsParam() {
                            @Override
                            public String getMcpServerUrl() {
                                return "http://example.com";
                            }
                        });
        String p1 =
                (String)
                        invokePrivate(
                                ext, "getMcpServerPath", new Class[] {String.class}, "/index");
        assertEquals("http://example.com/index", p1);

        ext =
                new ExtensionShyHurricaneForwarder(
                        new ShyHurricaneOptionsParam() {
                            @Override
                            public String getMcpServerUrl() {
                                return "http://example.com/";
                            }
                        });
        String p2 =
                (String)
                        invokePrivate(ext, "getMcpServerPath", new Class[] {String.class}, "index");
        assertEquals("http://example.com/index", p2);
    }

    @Test
    void shouldSkip_rules() throws Exception {
        // null / empty
        assertFalse(
                (Boolean)
                        invokePrivate(
                                ext, "shouldSkip", new Class[] {String.class}, (Object) null));
        assertFalse((Boolean) invokePrivate(ext, "shouldSkip", new Class[] {String.class}, ""));

        // images except svg
        assertTrue(
                (Boolean)
                        invokePrivate(ext, "shouldSkip", new Class[] {String.class}, "image/png"));
        assertFalse(
                (Boolean)
                        invokePrivate(
                                ext, "shouldSkip", new Class[] {String.class}, "image/svg+xml"));

        // explicit skip types
        assertTrue(
                (Boolean)
                        invokePrivate(
                                ext, "shouldSkip", new Class[] {String.class}, "application/pdf"));
        assertTrue(
                (Boolean)
                        invokePrivate(
                                ext,
                                "shouldSkip",
                                new Class[] {String.class},
                                "application/octet-stream"));
        assertTrue(
                (Boolean)
                        invokePrivate(
                                ext,
                                "shouldSkip",
                                new Class[] {String.class},
                                "application/x-protobuf"));

        // prefix-based skips
        assertTrue(
                (Boolean)
                        invokePrivate(ext, "shouldSkip", new Class[] {String.class}, "video/mp4"));
        assertTrue(
                (Boolean)
                        invokePrivate(ext, "shouldSkip", new Class[] {String.class}, "font/woff"));

        // +json / +xml should NOT be skipped
        assertFalse(
                (Boolean)
                        invokePrivate(
                                ext,
                                "shouldSkip",
                                new Class[] {String.class},
                                "application/vnd.api+json"));
        assertFalse(
                (Boolean)
                        invokePrivate(
                                ext,
                                "shouldSkip",
                                new Class[] {String.class},
                                "application/hal+xml"));
    }

    @Test
    void eventReceived_appliesThresholdsAndDeduplicates() throws Exception {
        // Configure thresholds via injected param
        ext =
                new ExtensionShyHurricaneForwarder(
                        new ShyHurricaneOptionsParam() {
                            @Override
                            public int getMinConfidenceLevel() {
                                return 2;
                            }

                            @Override
                            public int getMinRiskLevel() {
                                return 2;
                            }
                        });

        // Access pendingAlerts via reflection
        @SuppressWarnings("unchecked")
        Queue<String> pending = (Queue<String>) getField(ext, "pendingAlerts");
        pending.clear();

        Map<String, String> base = new HashMap<>();
        base.put(AlertEventPublisher.PLUGIN_ID, "10001");
        base.put(AlertEventPublisher.NAME, "XSS");
        base.put(AlertEventPublisher.ALERT_ID, "42");

        // Below thresholds -> ignored
        Map<String, String> low = new HashMap<>(base);
        low.put(AlertEventPublisher.CONFIDENCE, "1");
        low.put(AlertEventPublisher.RISK, "1");
        ext.eventReceived(fakeEvent(low));
        assertTrue(pending.isEmpty());

        // Meets thresholds -> queued once
        Map<String, String> ok = new HashMap<>(base);
        ok.put(AlertEventPublisher.CONFIDENCE, "3");
        ok.put(AlertEventPublisher.RISK, "3");
        ext.eventReceived(fakeEvent(ok));
        assertEquals(1, pending.size());

        // Same fingerprint again -> ignored due to de-dup
        ext.eventReceived(fakeEvent(ok));
        assertEquals(1, pending.size());
    }

    @Test
    void alertFingerprint_isDeterministic() throws Exception {
        Map<String, String> m = new HashMap<>();
        m.put(AlertEventPublisher.PLUGIN_ID, "10001");
        m.put(AlertEventPublisher.NAME, "Test");
        m.put(AlertEventPublisher.RISK, "2");
        m.put(AlertEventPublisher.CONFIDENCE, "3");
        Object fp = invokePrivate(ext, "alertFingerprint", new Class[] {Event.class}, fakeEvent(m));
        assertEquals(
                fp,
                invokePrivate(ext, "alertFingerprint", new Class[] {Event.class}, fakeEvent(m)));
        for (String key :
                new String[] {
                    AlertEventPublisher.ALERT_ID, AlertEventPublisher.URI, AlertEventPublisher.PARAM
                }) {
            Map<String, String> distinct = new HashMap<>(m);
            distinct.put(key, "http://example.com/a?q=exact%2Fvalue");
            assertNotEquals(
                    fp,
                    invokePrivate(
                            ext,
                            "alertFingerprint",
                            new Class[] {Event.class},
                            fakeEvent(distinct)));
        }
    }

    @Test
    void concurrentDuplicateEventsQueueOnceAndTupleSeparatorsCannotCollide() throws Exception {
        final Map<String, String> parameters = new HashMap<>();
        parameters.put(AlertEventPublisher.ALERT_ID, "42");
        parameters.put(AlertEventPublisher.PLUGIN_ID, "100/Name");
        parameters.put(AlertEventPublisher.NAME, "Tail");
        parameters.put(AlertEventPublisher.RISK, "3");
        parameters.put(AlertEventPublisher.CONFIDENCE, "3");
        parameters.put(AlertEventPublisher.URI, "http://example.com/a?q=one%2Ftwo");
        parameters.put(AlertEventPublisher.PARAM, "q");
        final var workers = java.util.concurrent.Executors.newFixedThreadPool(8);
        final var start = new java.util.concurrent.CountDownLatch(1);
        try {
            final var tasks = new java.util.ArrayList<java.util.concurrent.Future<?>>();
            for (int i = 0; i < 32; i++) {
                tasks.add(
                        workers.submit(
                                () -> {
                                    start.await();
                                    ext.eventReceived(fakeEvent(parameters));
                                    return null;
                                }));
            }
            start.countDown();
            for (final var task : tasks) task.get(5, java.util.concurrent.TimeUnit.SECONDS);
            assertEquals(1, ((Queue<?>) getField(ext, "pendingAlerts")).size());
            final var collision = new HashMap<>(parameters);
            collision.put(AlertEventPublisher.PLUGIN_ID, "100");
            collision.put(AlertEventPublisher.NAME, "Name/Tail");
            ext.eventReceived(fakeEvent(collision));
            assertEquals(2, ((Queue<?>) getField(ext, "pendingAlerts")).size());
        } finally {
            workers.shutdownNow();
            ext.unload();
        }
    }

    // Helpers
    private static Object invokePrivate(
            Object target, String name, Class<?>[] paramTypes, Object... args)
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Method m = target.getClass().getDeclaredMethod(name, paramTypes);
        m.setAccessible(true);
        return m.invoke(target, args);
    }

    private static Object getField(Object target, String name)
            throws NoSuchFieldException, IllegalAccessException {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(target);
    }

    private static Event fakeEvent(Map<String, String> params) {
        // Construct a concrete Event with only parameters set; publisher/target are unused by code
        // under test
        return new Event(null, "test", null, params);
    }
}
