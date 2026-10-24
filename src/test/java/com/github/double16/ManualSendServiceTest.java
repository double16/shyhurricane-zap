package com.github.double16;

import static com.github.double16.ForwardingTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;

class ManualSendServiceTest {
    @Test
    void sendsSingleAndMultipleMessagesWithoutAutomaticFiltersAndAllowsResend() throws Exception {
        try (final var support = new ForwardingTestSupport()) {
            final HttpMessage first = message();
            final HttpMessage second = message();
            support.sender.sendMessages(List.of(first, first, second));
            final Summary summary = support.completed();
            assertFalse(summary.warning());
            assertTrue(summary.text().contains("2 HTTP exchanges"));
            assertEquals(
                    2,
                    support.deliveries.size(),
                    "Different unsaved objects are distinct even with identical contents");
            final var entry = support.deliveries.remove();
            assertEquals("/index", entry.path());
            assertEquals(404, entry.body().path("response").path("status_code").asInt());
            assertEquals("request é", entry.body().path("request").path("body").asText());
            assertEquals(
                    "a;b", entry.body().path("request").path("headers").path("x-foo").asText());
            assertEquals("response ü", entry.body().path("response").path("body").asText());
            assertEquals(1.5, entry.body().path("response").path("rtt").asDouble());
            support.sender.sendMessages(List.of(first));
            assertTrue(support.completed().text().contains("1 HTTP exchanges"));
            assertEquals(2, support.deliveries.size());
        }
    }

    @Test
    void sendsAllDistinctFindingsAndSharedTrafficOnceRegardlessOfThresholds() throws Exception {
        try (final var support = new ForwardingTestSupport()) {
            final HttpMessage message = message();
            final Alert first = alert(1, message);
            final Alert sameId = alert(1, message);
            final Alert second = alert(2, message);
            final Alert unsaved = alert(-1, message);
            final Alert otherUnsaved = alert(-1, message);
            support.sender.sendAlerts(
                    List.of(first, first, sameId, second, unsaved, unsaved, otherUnsaved));
            assertTrue(support.completed().text().contains("4 findings and 1 HTTP exchanges"));
            assertEquals(5, support.deliveries.size());
            assertEquals("/findings", support.deliveries.remove().path());
            support.sender.sendAlerts(List.of(first));
            assertTrue(support.completed().text().contains("1 findings and 1 HTTP exchanges"));
        }
    }

    @Test
    void missingResponsesAreSkippedWithoutLosingFindings() throws Exception {
        try (final var support = new ForwardingTestSupport()) {
            final HttpMessage incomplete = new HttpMessage(message().getRequestHeader());
            support.sender.sendAlerts(List.of(alert(1, incomplete), alert(2, null)));
            final Summary summary = support.completed();
            assertTrue(summary.warning());
            assertTrue(summary.text().contains("2 findings and 0 HTTP exchanges; skipped 2"));
            assertEquals(2, support.deliveries.size());
            final HttpMessage noRequest = message();
            noRequest.setRequestHeader(new org.parosproxy.paros.network.HttpRequestHeader());
            support.sender.sendMessages(List.of(noRequest, incomplete));
            assertTrue(support.completed().text().contains("skipped 2"));
        }
    }

    @Test
    void resolvesStoredMessagesOffEdtAndDeduplicatesByHistoryId() throws Exception {
        try (final var support = new ForwardingTestSupport()) {
            final HttpMessage message = message();
            final HistoryReference first = mock(HistoryReference.class);
            final HistoryReference duplicate = mock(HistoryReference.class);
            when(first.getHistoryId()).thenReturn(42);
            when(duplicate.getHistoryId()).thenReturn(42);
            when(first.getHttpMessage())
                    .thenAnswer(
                            invocation -> {
                                assertFalse(SwingUtilities.isEventDispatchThread());
                                return message;
                            });
            final var selected = new ArrayList<>(List.of(first, duplicate));
            SwingUtilities.invokeAndWait(() -> support.sender.sendHistory(selected));
            selected.clear();
            assertTrue(support.completed().text().contains("1 HTTP exchanges"));
            verify(duplicate, never()).getHttpMessage();
            final Alert alert = alert(1, null);
            alert.setHistoryRef(first);
            support.sender.sendAlerts(List.of(alert, alert(2, message)));
            assertTrue(support.completed().text().contains("2 findings and 1 HTTP exchanges"));

            message.setHistoryRef(first);
            final HttpMessage duplicateMessage = message();
            duplicateMessage.setHistoryRef(duplicate);
            support.sender.sendMessages(List.of(message, duplicateMessage));
            assertTrue(support.completed().text().contains("1 HTTP exchanges"));
        }
    }

    @Test
    void continuesAfterFindingsHttpAndDatabaseFailures() throws Exception {
        try (final var support = new ForwardingTestSupport()) {
            support.findingsStatus = 500;
            support.sender.sendAlerts(List.of(alert(1, message())));
            final Summary partial = support.completed();
            assertTrue(partial.warning());
            assertTrue(partial.text().contains("0 findings and 1 HTTP exchanges"));
            assertTrue(partial.text().contains("1 failures"));
            assertFalse(partial.text().contains("example.test"));
            support.indexStatus = 400;
            support.sender.sendMessages(List.of(message(), message()));
            assertTrue(support.completed().text().contains("2 failures"));
            final HistoryReference broken = mock(HistoryReference.class);
            when(broken.getHistoryId()).thenReturn(1);
            when(broken.getHttpMessage())
                    .thenThrow(new org.parosproxy.paros.db.DatabaseException("secret"));
            final HistoryReference good = mock(HistoryReference.class);
            when(good.getHistoryId()).thenReturn(2);
            when(good.getHttpMessage()).thenReturn(message());
            support.indexStatus = 204;
            support.sender.sendHistory(List.of(broken, good));
            final Summary recovered = support.completed();
            assertTrue(recovered.text().contains("1 HTTP exchanges"));
            assertTrue(recovered.text().contains("1 failures"));
            assertFalse(recovered.text().contains("secret"));
        }
    }

    @Test
    void boundsQueueRejectsWithoutBlockingAndReleasesPendingBatchesOnClose() throws Exception {
        try (final var support = new ForwardingTestSupport()) {
            final CountDownLatch started = new CountDownLatch(1);
            final CountDownLatch interrupted = new CountDownLatch(1);
            final HistoryReference blocking = mock(HistoryReference.class);
            when(blocking.getHttpMessage())
                    .thenAnswer(
                            invocation -> {
                                started.countDown();
                                try {
                                    new CountDownLatch(1).await();
                                } catch (InterruptedException e) {
                                    Thread.currentThread().interrupt();
                                    interrupted.countDown();
                                }
                                return message();
                            });
            support.sender.sendHistory(List.of(blocking, blocking));
            assertTrue(started.await(5, TimeUnit.SECONDS));
            for (int i = 0; i < 16; i++) support.sender.sendMessages(List.of(message()));
            support.sender.sendMessages(List.of(message()));
            assertTrue(support.completed().text().contains("not queued"));
            support.sender.close();
            assertTrue(interrupted.await(5, TimeUnit.SECONDS));
            support.sender.sendAlerts(List.of(alert(1, message())));
            assertTrue(support.completed().text().contains("not queued"));
        }
    }

    @Test
    void messageSnapshotIsUnaffectedByLaterEditorChanges() throws Exception {
        final HttpMessage original = message();
        final var source = ManualSendService.MessageSource.message(original);
        original.setRequestBody("changed");
        original.setResponseBody("changed");
        assertEquals("request é", source.loader().load().getRequestBody().toString());
        assertEquals("response ü", source.loader().load().getResponseBody().toString());
    }

    @Test
    void emptyAndMisconfiguredBatchesProduceSummaries() throws Exception {
        try (final var support = new ForwardingTestSupport()) {
            support.sender.sendMessages(List.of());
            final Summary empty = support.completed();
            assertFalse(empty.warning());
            assertTrue(empty.text().contains("0 findings and 0 HTTP exchanges"));
        }
        final java.util.concurrent.BlockingQueue<String> reported =
                new java.util.concurrent.LinkedBlockingQueue<>();
        try (final var service =
                new ManualSendService(
                        () -> {
                            throw new IllegalStateException("secret");
                        },
                        (text, warning) -> {
                            assertTrue(warning);
                            reported.add(text);
                        })) {
            service.sendAlerts(List.of());
            final String report = reported.poll(5, TimeUnit.SECONDS);
            assertNotNull(report);
            assertFalse(report.contains("secret"));
        }
    }
}
