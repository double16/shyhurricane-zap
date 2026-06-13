package com.github.double16;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;

import java.lang.reflect.Method;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ExtensionShyHurricaneForwarderHeadersTest {

    private ExtensionShyHurricaneForwarder ext;

    @BeforeEach
    void setUp() {
        ext = new ExtensionShyHurricaneForwarder();
    }

    @SuppressWarnings("unchecked")
    @Test
    void toKatanaHeaders_lowercasesAndMergesDuplicates() throws Exception {
        // Build a request header with duplicate header names and mixed case
        String raw = "GET http://example.com/ HTTP/1.1\r\n" +
                "X-FOO: a\r\n" +
                "x-foo: b\r\n" +
                "Content-Type: Text/Plain\r\n" +
                "\r\n";
        HttpRequestHeader req = new HttpRequestHeader(raw);

        Method m = ExtensionShyHurricaneForwarder.class
                .getDeclaredMethod("toKatanaHeaders", org.parosproxy.paros.network.HttpHeader.class);
        m.setAccessible(true);
        Map<String, String> kat = (Map<String, String>) m.invoke(ext, req);

        assertEquals("a;b", kat.get("x-foo"));
        assertEquals("Text/Plain", kat.get("content-type"));
        // Ensure no original-case keys exist
        assertFalse(kat.containsKey("X-FOO"));
        assertFalse(kat.containsKey("Content-Type"));
    }

    @Test
    void onHttpResponseReceive_skipsWhenInitiatorNotSelected() throws Exception {
        // Configure: only selected initiators are processed
        setParam(ext, new ShyHurricaneOptionsParam() {
            @Override public boolean isInitiatorsAll() { return false; }
            @Override public String getInitiatorsSelectedCsv() { return "1,2"; }
            @Override public boolean isInitiatorSelected(int id) { return id == 1 || id == 2; }
            @Override public boolean isOnlyInScope() { return false; }
        });

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(new HttpRequestHeader("GET http://example.com/ HTTP/1.1\r\n\r\n"));
        HttpResponseHeader res = new HttpResponseHeader();
        res.setStatusCode(200);
        res.setHeader("Content-Type", "application/json");
        msg.setResponseHeader(res);

        // Initiator 3 is NOT selected; method should return early without throwing
        ext.onHttpResponseReceive(msg, 3, null);
    }

    @Test
    void onHttpResponseReceive_skipsOnContentType() throws Exception {
        // All initiators allowed, not only in scope
        setParam(ext, new ShyHurricaneOptionsParam() {
            @Override public boolean isInitiatorsAll() { return true; }
            @Override public boolean isOnlyInScope() { return false; }
        });

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(new HttpRequestHeader("GET http://example.com/ HTTP/1.1\r\n\r\n"));
        HttpResponseHeader res = new HttpResponseHeader();
        res.setStatusCode(200);
        // image/png should be skipped by the filtering logic
        res.setHeader("Content-Type", "image/png");
        msg.setResponseHeader(res);

        // Should return early; just assert no exception is thrown
        ext.onHttpResponseReceive(msg, 0, null);
    }

    private static void setParam(ExtensionShyHurricaneForwarder target, ShyHurricaneOptionsParam p) {
        try {
            var f = target.getClass().getDeclaredField("param");
            f.setAccessible(true);
            f.set(target, p);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }
}
