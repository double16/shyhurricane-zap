package com.github.double16;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.extension.alert.AlertEventPublisher;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.junit.jupiter.api.Assertions.*;

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
        setParam(ext, new ShyHurricaneOptionsParam() {
            @Override public boolean isOnlyInScope() { return false; }
        });
        assertFalse(ext.isOnlyInScope());

        setParam(ext, new ShyHurricaneOptionsParam() {
            @Override public boolean isOnlyInScope() { return true; }
        });
        assertTrue(ext.isOnlyInScope());
    }

    @Test
    void getMcpServerPath_joinsWithSingleSlash() throws Exception {
        setParam(ext, new ShyHurricaneOptionsParam() {
            @Override public String getMcpServerUrl() { return "http://example.com"; }
        });
        String p1 = (String) invokePrivate(ext, "getMcpServerPath", new Class[]{String.class}, "/index");
        assertEquals("http://example.com/index", p1);

        setParam(ext, new ShyHurricaneOptionsParam() {
            @Override public String getMcpServerUrl() { return "http://example.com/"; }
        });
        String p2 = (String) invokePrivate(ext, "getMcpServerPath", new Class[]{String.class}, "index");
        assertEquals("http://example.com/index", p2);
    }

    @Test
    void shouldSkip_rules() throws Exception {
        // null / empty
        assertFalse((Boolean) invokePrivate(ext, "shouldSkip", new Class[]{String.class}, (Object) null));
        assertFalse((Boolean) invokePrivate(ext, "shouldSkip", new Class[]{String.class}, ""));

        // images except svg
        assertTrue((Boolean) invokePrivate(ext, "shouldSkip", new Class[]{String.class}, "image/png"));
        assertFalse((Boolean) invokePrivate(ext, "shouldSkip", new Class[]{String.class}, "image/svg+xml"));

        // explicit skip types
        assertTrue((Boolean) invokePrivate(ext, "shouldSkip", new Class[]{String.class}, "application/pdf"));
        assertTrue((Boolean) invokePrivate(ext, "shouldSkip", new Class[]{String.class}, "application/octet-stream"));
        assertTrue((Boolean) invokePrivate(ext, "shouldSkip", new Class[]{String.class}, "application/x-protobuf"));

        // prefix-based skips
        assertTrue((Boolean) invokePrivate(ext, "shouldSkip", new Class[]{String.class}, "video/mp4"));
        assertTrue((Boolean) invokePrivate(ext, "shouldSkip", new Class[]{String.class}, "font/woff"));

        // +json / +xml should NOT be skipped
        assertFalse((Boolean) invokePrivate(ext, "shouldSkip", new Class[]{String.class}, "application/vnd.api+json"));
        assertFalse((Boolean) invokePrivate(ext, "shouldSkip", new Class[]{String.class}, "application/hal+xml"));
    }

    @Test
    void eventReceived_appliesThresholdsAndDeduplicates() throws Exception {
        // Configure thresholds via injected param
        setParam(ext, new ShyHurricaneOptionsParam() {
            @Override public int getMinConfidenceLevel() { return 2; }
            @Override public int getMinRiskLevel() { return 2; }
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
        String fp = (String) invokePrivate(ext, "alertFingerprint", new Class[]{Event.class}, fakeEvent(m));
        assertEquals("10001/Test/2/3", fp);
    }

    // Helpers
    private static Object invokePrivate(Object target, String name, Class<?>[] paramTypes, Object... args)
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Method m = target.getClass().getDeclaredMethod(name, paramTypes);
        m.setAccessible(true);
        return m.invoke(target, args);
    }

    private static Object getField(Object target, String name) throws NoSuchFieldException, IllegalAccessException {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(target);
    }

    private static void setParam(ExtensionShyHurricaneForwarder target, ShyHurricaneOptionsParam p) {
        try {
            Field f = target.getClass().getDeclaredField("param");
            f.setAccessible(true);
            f.set(target, p);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    private static Event fakeEvent(Map<String, String> params) {
        // Construct a concrete Event with only parameters set; publisher/target are unused by code under test
        return new Event(null, "test", null, params);
    }
}
