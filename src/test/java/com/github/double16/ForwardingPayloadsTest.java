package com.github.double16;

import static com.github.double16.ForwardingTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;

class ForwardingPayloadsTest {
    @Test
    void findingsContainAllAvailableDetailsAndKeepExistingWireShape() throws Exception {
        final Alert alert = alert(1, message());
        alert.setDetail(
                "Summary",
                "http://example.test/",
                "parameter",
                "attack",
                "Other info",
                "Fix it",
                "ref1\nref2",
                "evidence",
                79,
                1,
                message());
        alert.setEvidence("evidence");
        alert.setInputVector("input vector");
        final Map<String, Object> payload = ForwardingPayloads.finding(alert);
        assertEquals(java.util.Set.of("target", "title", "markdown"), payload.keySet());
        assertEquals("Example finding at http://example.test/", payload.get("title"));
        final String markdown = payload.get("markdown").toString();
        for (final String detail :
                new String[] {
                    "Summary",
                    "Other info",
                    "Plugin ID: 123",
                    "evidence",
                    "POST",
                    "parameter",
                    "request é",
                    "input vector",
                    "attack",
                    "Fix it",
                    "CWE-79",
                    "WASC-1",
                    "- ref1\n- ref2"
                }) {
            assertTrue(markdown.contains(detail), detail);
        }
    }

    @Test
    void findingsOmitEmptyDetailsAndDefaultToGetWithoutAMessage() {
        final Alert alert = alert(1, null);
        final String markdown = ForwardingPayloads.finding(alert).get("markdown").toString();
        assertTrue(markdown.contains("GET http://example.test/resource"));
        assertFalse(markdown.contains("**References**"));
        assertFalse(markdown.contains("**Solution**"));
        assertFalse(markdown.contains("Parameter:"));
        alert.setReference("ref");
        assertTrue(
                ForwardingPayloads.finding(alert)
                        .get("markdown")
                        .toString()
                        .contains("**References**"));
        alert.setReference("");
        alert.setWascId(1);
        assertTrue(ForwardingPayloads.finding(alert).get("markdown").toString().contains("WASC-1"));
        alert.setWascId(0);
        alert.setCweId(79);
        assertTrue(ForwardingPayloads.finding(alert).get("markdown").toString().contains("CWE-79"));
    }

    @Test
    void headerNamesAreLocaleIndependent() throws Exception {
        final Locale previous = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            final HttpMessage message = message();
            message.getRequestHeader().setHeader("X-ID", "value");
            assertEquals(
                    "value", ForwardingPayloads.headers(message.getRequestHeader()).get("x-id"));
        } finally {
            Locale.setDefault(previous);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void undecodableBodiesDoNotPreventSendingHeaders() throws Exception {
        final HttpMessage message = spy(message());
        doThrow(new IllegalStateException("unreadable")).when(message).getRequestBody();
        doThrow(new IllegalStateException("unreadable")).when(message).getResponseBody();
        final Map<String, Object> payload = ForwardingPayloads.index(message);
        assertFalse(((Map<String, Object>) payload.get("request")).containsKey("body"));
        assertFalse(((Map<String, Object>) payload.get("response")).containsKey("body"));
    }
}
