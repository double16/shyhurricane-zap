package com.github.double16;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Map;

/** Shared transport; failures contain no target URLs, response bodies, or credentials. */
final class ShyHurricaneClient {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ShyHurricaneClient() {}

    static void post(final String url, final Map<String, Object> data) throws IOException {
        post(url, data, 5_000, 15_000);
    }

    static void post(
            final String url,
            final Map<String, Object> data,
            final int connectTimeout,
            final int readTimeout)
            throws IOException {
        final byte[] body = MAPPER.writeValueAsBytes(data);
        final HttpURLConnection connection =
                (HttpURLConnection) URI.create(url).toURL().openConnection();
        try {
            connection.setConnectTimeout(connectTimeout);
            connection.setReadTimeout(readTimeout);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            connection.setDoOutput(true);
            connection.setFixedLengthStreamingMode(body.length);
            try (var output = connection.getOutputStream()) {
                output.write(body);
            }
            final int status = connection.getResponseCode();
            if (status / 100 != 2) {
                throw new IOException("ShyHurricane returned HTTP " + status);
            }
            // There is no processing between acquiring and closing this stream.
            connection.getInputStream().close();
        } finally {
            connection.disconnect();
        }
    }
}
