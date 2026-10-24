package com.github.double16;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Supplier;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;

/** Explicit sends have no automatic eligibility checks or persistent duplicate suppression. */
final class ManualSendService implements AutoCloseable {
    @FunctionalInterface
    interface MessageLoader {
        HttpMessage load() throws Exception;
    }

    record MessageSource(Object identity, int historyId, MessageLoader loader) {
        static MessageSource history(final HistoryReference reference) {
            return new MessageSource(
                    reference, reference.getHistoryId(), reference::getHttpMessage);
        }

        static MessageSource message(final HttpMessage message) {
            final HistoryReference reference = message.getHistoryRef();
            final HttpMessage snapshot = message.cloneAll();
            snapshot.setTimeElapsedMillis(message.getTimeElapsedMillis());
            return new MessageSource(
                    message, reference == null ? 0 : reference.getHistoryId(), () -> snapshot);
        }
    }

    private final Supplier<String> serverUrl;
    private final BiConsumer<String, Boolean> reporter;
    private final ThreadPoolExecutor worker;

    ManualSendService(
            final Supplier<String> serverUrl, final BiConsumer<String, Boolean> reporter) {
        this.serverUrl = Objects.requireNonNull(serverUrl);
        this.reporter = Objects.requireNonNull(reporter);
        worker =
                new ThreadPoolExecutor(
                        1,
                        1,
                        0,
                        TimeUnit.MILLISECONDS,
                        new ArrayBlockingQueue<>(16),
                        runnable -> {
                            final Thread thread = new Thread(runnable, "ShyHurricane-manual-send");
                            thread.setDaemon(true);
                            return thread;
                        });
    }

    void sendAlerts(final Collection<Alert> selection) {
        final List<Alert> alerts = List.copyOf(selection);
        submit(() -> send(alerts, List.of()));
    }

    void sendMessages(final Collection<HttpMessage> selection) {
        final List<MessageSource> messages =
                selection.stream().map(MessageSource::message).toList();
        sendSources(messages);
    }

    void sendHistory(final Collection<HistoryReference> selection) {
        sendSources(selection.stream().map(MessageSource::history).toList());
    }

    private void sendSources(final List<MessageSource> selection) {
        submit(() -> send(List.of(), selection));
    }

    private void submit(final Runnable task) {
        try {
            worker.execute(
                    () -> {
                        try {
                            task.run();
                        } catch (RuntimeException e) {
                            reporter.accept(
                                    "Selection could not be sent. Check the ShyHurricane configuration and try again.",
                                    true);
                        }
                    });
        } catch (RejectedExecutionException e) {
            reporter.accept(
                    "Selection was not queued: the sender is busy or stopped. Try again after pending sends finish.",
                    true);
        }
    }

    private void send(final List<Alert> alerts, final List<MessageSource> selectedMessages) {
        int findings = 0;
        int exchanges = 0;
        int skipped = 0;
        int failures = 0;
        final Set<Integer> alertIds = new HashSet<>();
        final Set<Alert> alertObjects = Collections.newSetFromMap(new IdentityHashMap<>());
        final List<MessageSource> messages = new ArrayList<>(selectedMessages);
        final String baseUrl = serverUrl.get().replaceAll("/+$", "");
        for (final Alert alert : alerts) {
            if (Thread.currentThread().isInterrupted()) {
                return;
            }
            if (!(alert.getAlertId() > 0
                    ? alertIds.add(alert.getAlertId())
                    : alertObjects.add(alert))) {
                continue;
            }
            try {
                ShyHurricaneClient.post(baseUrl + "/findings", ForwardingPayloads.finding(alert));
                findings++;
            } catch (Exception e) {
                failures++;
            }
            // Loading a stored alert message may access the database, so it stays on this worker.
            final HistoryReference reference = alert.getHistoryRef();
            if (reference != null) {
                messages.add(MessageSource.history(reference));
            } else {
                messages.add(new MessageSource(alert, 0, alert::getMessage));
            }
        }
        final Set<Integer> historyIds = new HashSet<>();
        final Set<Object> sources = Collections.newSetFromMap(new IdentityHashMap<>());
        final Set<HttpMessage> loadedMessages = Collections.newSetFromMap(new IdentityHashMap<>());
        for (final MessageSource source : messages) {
            if (Thread.currentThread().isInterrupted()) {
                return;
            }
            if (!(source.historyId() > 0
                    ? historyIds.add(source.historyId())
                    : sources.add(source.identity()))) {
                continue;
            }
            try {
                final HttpMessage message = source.loader().load();
                if (Thread.currentThread().isInterrupted()) {
                    return;
                }
                if (message != null && !loadedMessages.add(message)) {
                    continue;
                }
                if (message == null
                        || message.getRequestHeader().isEmpty()
                        || message.getResponseHeader().isEmpty()
                        || message.getResponseHeader().getStatusCode() <= 0) {
                    skipped++;
                    continue;
                }
                ShyHurricaneClient.post(baseUrl + "/index", ForwardingPayloads.index(message));
                exchanges++;
            } catch (Exception e) {
                failures++;
            }
        }
        if (Thread.currentThread().isInterrupted()) {
            return;
        }
        reporter.accept(
                String.format(
                        "Sent %d findings and %d HTTP exchanges; skipped %d unavailable/incomplete exchanges; %d failures.%s",
                        findings,
                        exchanges,
                        skipped,
                        failures,
                        failures > 0
                                ? " Check the configured server URL and server availability, then select failed items to try again."
                                : ""),
                skipped > 0 || failures > 0);
    }

    @Override
    public void close() {
        worker.shutdownNow();
    }
}
