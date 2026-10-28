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
    @SuppressWarnings("unchecked")
    private static Map<String, Object> metadata(final Alert alert) {
        return (Map<String, Object>) ForwardingPayloads.finding(alert).get("metadata");
    }

    @Test
    void mapsEverySeverityAndConfidence() {
        final Alert alert = alert(0, null);
        final String[] severities = {"informational", "low", "medium", "high"};
        for (int risk = 0; risk < severities.length; risk++) {
            alert.setRisk(risk);
            assertEquals(severities[risk], metadata(alert).get("severity"));
            assertEquals(Alert.MSG_RISK[risk], metadata(alert).get("native_severity"));
        }
        final String[] confidences = {null, "low", "medium", "high", "high"};
        for (int confidence = 0; confidence < confidences.length; confidence++) {
            alert.setConfidence(confidence);
            final var values = metadata(alert);
            assertEquals(confidences[confidence], values.get("confidence"));
            assertEquals(Alert.MSG_CONFIDENCE[confidence], values.get("native_confidence"));
            assertEquals(
                    confidence == 0 ? "false_positive" : "unverified",
                    values.get("verification_status"));
        }
        assertEquals("0", metadata(alert).get("source_finding_id"));
    }

    @Test
    void unsupportedLabelsAndSparseMetadataAreSafe() throws Exception {
        final Alert alert = spy(alert(-1, null));
        for (final int invalid : new int[] {-2, 100}) {
            doReturn(invalid).when(alert).getRisk();
            doReturn(invalid).when(alert).getConfidence();
            final var values = metadata(alert);
            assertEquals(
                    Map.of(
                            "source",
                            "zap",
                            "rule_id",
                            "123",
                            "severity",
                            "unknown",
                            "confidence",
                            "unknown",
                            "verification_status",
                            "unverified"),
                    values);
            assertNotNull(ForwardingPayloads.finding(alert).get("markdown"));
        }
        final var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        final var json =
                mapper.readTree(mapper.writeValueAsString(ForwardingPayloads.finding(alert)));
        assertEquals("unknown", json.path("metadata").path("severity").asText());
        assertFalse(
                mapper.readTree(
                                mapper.writeValueAsString(
                                        Map.of(
                                                "target",
                                                "http://example.com/",
                                                "title",
                                                "Legacy",
                                                "markdown",
                                                "Text")))
                        .has("metadata"));
    }

    @Test
    void mapsOnlyExplicitCwesAndOmitsEmptyParameters() {
        final Alert alert = alert(1, null);
        final Map<Integer, String> categories =
                Map.of(79, "xss", 78, "injection", 89, "injection", 918, "ssrf");
        categories.forEach(
                (cwe, category) -> {
                    alert.setCweId(cwe);
                    assertEquals(
                            java.util.List.of(category),
                            metadata(alert).get("vulnerability_types"));
                    assertEquals(java.util.List.of("CWE-" + cwe), metadata(alert).get("cwe_ids"));
                });
        for (final int cwe : new int[] {-1, 0, 22}) {
            alert.setCweId(cwe);
            assertFalse(metadata(alert).containsKey("vulnerability_types"));
            assertEquals(cwe > 0, metadata(alert).containsKey("cwe_ids"));
        }
        for (final String parameter : new String[] {null, "", "  "}) {
            alert.setParam(parameter);
            assertFalse(metadata(alert).containsKey("parameter"));
        }
    }

    @Test
    void completeSerializationPreservesUrlAndExcludesSensitiveMetadata() throws Exception {
        final Alert alert = alert(7, message());
        alert.setUri("http://example.com/a?q=one%2Ftwo&token=exact+value");
        alert.setParam("q");
        alert.setCweId(79);
        alert.setConfidence(Alert.CONFIDENCE_USER_CONFIRMED);
        alert.getMessage().getRequestHeader().setHeader("Authorization", "secret");
        final var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        final var json =
                mapper.readTree(mapper.writeValueAsString(ForwardingPayloads.finding(alert)));
        assertEquals(alert.getUri(), json.path("target").asText());
        assertEquals("Example finding at " + alert.getUri(), json.path("title").asText());
        assertEquals(
                mapper.valueToTree(
                        Map.ofEntries(
                                Map.entry("source", "zap"),
                                Map.entry("rule_id", "123"),
                                Map.entry("source_finding_id", "7"),
                                Map.entry("severity", "informational"),
                                Map.entry("native_severity", Alert.MSG_RISK[0]),
                                Map.entry("confidence", "high"),
                                Map.entry("native_confidence", Alert.MSG_CONFIDENCE[4]),
                                Map.entry("verification_status", "unverified"),
                                Map.entry("affected_method", "POST"),
                                Map.entry("cwe_ids", java.util.List.of("CWE-79")),
                                Map.entry("vulnerability_types", java.util.List.of("xss")),
                                Map.entry("parameter", Map.of("name", "q")))),
                json.path("metadata"));
    }

    @Test
    void methodsComeOnlyFromMessagesAndUseRootLocale() throws Exception {
        final Alert alert = spy(alert(1, null));
        doReturn("DELETE").when(alert).getMethod();
        assertFalse(metadata(alert).containsKey("affected_method"));
        final HttpMessage message = mock(HttpMessage.class);
        final var header = mock(org.parosproxy.paros.network.HttpRequestHeader.class);
        when(message.getRequestHeader()).thenReturn(header);
        doReturn(message).when(alert).getMessage();
        for (final String method : new String[] {null, "", "  "}) {
            when(header.getMethod()).thenReturn(method);
            assertFalse(metadata(alert).containsKey("affected_method"));
        }
        final Locale previous = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            when(header.getMethod()).thenReturn("options");
            assertEquals("OPTIONS", metadata(alert).get("affected_method"));
        } finally {
            Locale.setDefault(previous);
        }
    }

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
        assertEquals(java.util.Set.of("target", "title", "markdown", "metadata"), payload.keySet());
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
    void validMarkdownRemainsUnchanged() {
        final Alert alert = alert(1, null);
        alert.setUri("http://target.local/resource");
        final String expected =
                "# Example finding at http://target.local/resource\n\n"
                        + "**Summary**\nDescription\nRisk: "
                        + Alert.MSG_RISK[Alert.RISK_INFO]
                        + "\nConfidence: "
                        + Alert.MSG_CONFIDENCE[Alert.CONFIDENCE_FALSE_POSITIVE]
                        + "\n\n**Discovery Method**\nDiscovered by OWASP ZAP (Plugin ID: 123)\n"
                        + "\n**Reproduction Steps**\nAccess the following URL: `GET http://target.local/resource`\n";
        assertEquals(expected, ForwardingPayloads.finding(alert).get("markdown"));
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
