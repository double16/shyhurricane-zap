package com.github.double16;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;

final class ForwardingTestSupport implements AutoCloseable {
    record Delivery(String path, JsonNode body, String contentType) {}

    record Summary(String text, boolean warning) {}

    final BlockingQueue<Delivery> deliveries = new LinkedBlockingQueue<>();
    final BlockingQueue<Summary> summaries = new LinkedBlockingQueue<>();
    final HttpServer server;
    final ManualSendService sender;
    volatile int findingsStatus = 204;
    volatile int indexStatus = 204;

    ForwardingTestSupport() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(
                "/",
                exchange -> {
                    try {
                        final JsonNode body =
                                new ObjectMapper().readTree(exchange.getRequestBody());
                        final String path = exchange.getRequestURI().getPath();
                        deliveries.add(
                                new Delivery(
                                        path,
                                        body,
                                        exchange.getRequestHeaders().getFirst("Content-Type")));
                        exchange.sendResponseHeaders(
                                path.endsWith("/findings") ? findingsStatus : indexStatus, -1);
                    } finally {
                        exchange.close();
                    }
                });
        server.start();
        sender =
                new ManualSendService(
                        () -> url() + "/",
                        (text, warning) -> summaries.add(new Summary(text, warning)));
    }

    String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    Summary completed() throws InterruptedException {
        final Summary summary = summaries.poll(10, TimeUnit.SECONDS);
        org.junit.jupiter.api.Assertions.assertNotNull(summary, "Manual batch did not finish");
        return summary;
    }

    static HttpMessage message() throws Exception {
        final HttpMessage message = new HttpMessage();
        message.setRequestHeader(
                new HttpRequestHeader(
                        "POST http://example.test/resource HTTP/1.1\r\nX-FOO: a\r\nx-foo: b\r\n\r\n"));
        message.setRequestBody("request é");
        message.setResponseHeader(
                new HttpResponseHeader(
                        "HTTP/1.1 404 Not Found\r\nContent-Type: image/png\r\n\r\n"));
        message.setResponseBody("response ü");
        message.setTimeElapsedMillis(1500);
        return message;
    }

    static Alert alert(final int id, final HttpMessage message) {
        final Alert alert =
                new Alert(123, Alert.RISK_INFO, Alert.CONFIDENCE_FALSE_POSITIVE, "Example finding");
        alert.setAlertId(id);
        alert.setDetail(
                "Description",
                "http://example.test/resource",
                "",
                "",
                "",
                "",
                "",
                "",
                0,
                0,
                message);
        return alert;
    }

    @Override
    public void close() {
        sender.close();
        server.stop(0);
    }
}
