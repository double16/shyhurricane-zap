package com.github.double16;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class ShyHurricaneClientTest {
    @Test
    void postsUtf8JsonAndRejectsErrorsAndRedirects() throws Exception {
        try (final var support = new ForwardingTestSupport()) {
            ShyHurricaneClient.post(support.url() + "/index", Map.of("value", "éü"));
            final var delivery = support.deliveries.remove();
            assertEquals("éü", delivery.body().get("value").asText());
            assertEquals("application/json; charset=UTF-8", delivery.contentType());
            support.indexStatus = 500;
            final IOException error =
                    assertThrows(
                            IOException.class,
                            () -> ShyHurricaneClient.post(support.url() + "/index", Map.of()));
            assertEquals("ShyHurricane returned HTTP 500", error.getMessage());
            support.indexStatus = 302;
            assertThrows(
                    IOException.class,
                    () -> ShyHurricaneClient.post(support.url() + "/index", Map.of()));
            assertEquals(
                    2,
                    support.deliveries.size(),
                    "Redirects must not forward data to another endpoint");
            support.indexStatus = 101;
            assertThrows(
                    IOException.class,
                    () -> ShyHurricaneClient.post(support.url() + "/index", Map.of()));
        }
    }

    @Test
    void readTimeoutClosesConnectionWithoutWaitingForServer() throws Exception {
        final HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        final CountDownLatch received = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        server.createContext(
                "/",
                exchange -> {
                    received.countDown();
                    try {
                        release.await(5, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        exchange.close();
                    }
                });
        server.start();
        try {
            assertThrows(
                    SocketTimeoutException.class,
                    () ->
                            ShyHurricaneClient.post(
                                    "http://127.0.0.1:" + server.getAddress().getPort(),
                                    Map.of(),
                                    1000,
                                    100));
            assertTrue(received.await(2, TimeUnit.SECONDS));
        } finally {
            release.countDown();
            server.stop(0);
        }
    }
}
