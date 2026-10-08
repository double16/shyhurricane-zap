package com.github.double16;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.configuration.XMLConfiguration;
import java.lang.reflect.Method;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ExtensionShyHurricaneForwarderHeadersTest {

    private ExtensionShyHurricaneForwarder ext;

    @BeforeEach
    void setUp() {
        ext = new ExtensionShyHurricaneForwarder();
    }

    @Test
    void onHttpResponseReceive_postsOnlySelectedStatuses() throws Exception {
        List<Integer> received = java.util.Collections.synchronizedList(new ArrayList<>());
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/index", exchange -> {
            try {
                assertEquals("POST", exchange.getRequestMethod());
                var payload = new ObjectMapper().readTree(exchange.getRequestBody());
                received.add(payload.get("response").get("status_code").asInt());
                exchange.sendResponseHeaders(204, -1);
            } finally {
                exchange.close();
            }
        });
        server.start();
        try {
            ShyHurricaneOptionsParam param = new ShyHurricaneOptionsParam();
            param.load(new XMLConfiguration());
            param.setOnlyInScope(false);
            param.setMcpServerUrl("http://127.0.0.1:" + server.getAddress().getPort());
            ext = new ExtensionShyHurricaneForwarder(param);
            int[] codes = {100, 101, 199, 200, 299, 300, 399, 400, 499, 500, 599, 600};
            for (int code : codes) sendResponse(code, "application/json");
            assertEquals(List.of(200, 299), received);

            received.clear();
            param.setStatusGroupSelected(2, false);
            param.setStatusGroupSelected(4, true);
            for (int code : codes) sendResponse(code, "application/json");
            assertEquals(List.of(400, 499), received);

            received.clear();
            for (int group = 2; group <= 5; group++) param.setStatusGroupSelected(group, true);
            for (int code : codes) sendResponse(code, "application/json");
            assertEquals(List.of(200, 299, 300, 399, 400, 499, 500, 599), received);
            sendResponse(200, "image/png");
            param.setInitiatorsAll(false);
            param.setInitiatorsSelectedCsv("");
            sendResponse(200, "application/json");
            assertEquals(8, received.size());

            received.clear();
            param.setInitiatorsAll(true);
            for (int group = 2; group <= 5; group++) param.setStatusGroupSelected(group, false);
            for (int code : codes) sendResponse(code, "application/json");
            assertTrue(received.isEmpty());
        } finally {
            server.stop(0);
        }
    }

    private void sendResponse(int statusCode, String contentType) throws Exception {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(new HttpRequestHeader("GET http://example.com/ HTTP/1.1\r\n\r\n"));
        HttpResponseHeader response = new HttpResponseHeader();
        response.setStatusCode(statusCode);
        response.setHeader("Content-Type", contentType);
        msg.setResponseHeader(response);
        ext.onHttpResponseReceive(msg, 0, null);
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
        ext = new ExtensionShyHurricaneForwarder(new ShyHurricaneOptionsParam() {
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
        ext = new ExtensionShyHurricaneForwarder(new ShyHurricaneOptionsParam() {
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
}
