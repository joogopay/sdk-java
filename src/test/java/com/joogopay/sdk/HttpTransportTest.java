package com.joogopay.sdk;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HttpTransportTest {
    private final java.util.List<Client.HttpClientTransport> transports = new java.util.ArrayList<>();

    private Client.HttpClientTransport transport(Duration timeout, int limit) {
        Client.HttpClientTransport transport = new Client.HttpClientTransport(timeout, limit);
        transports.add(transport);
        return transport;
    }

    @org.junit.jupiter.api.AfterEach
    void closeTransports() {
        for (Client.HttpClientTransport transport : transports) transport.close();
    }

    @Test
    void sendsExactBodyAndHeadersAndReadsErrorBody() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        byte[] expected = "{\"message\":\"hello\"}".getBytes(StandardCharsets.UTF_8);
        java.util.concurrent.atomic.AtomicReference<byte[]> received = new java.util.concurrent.atomic.AtomicReference<byte[]>();
        java.util.concurrent.atomic.AtomicReference<String> contentType = new java.util.concurrent.atomic.AtomicReference<String>();
        server.createContext("/test", exchange -> {
            java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
            try (java.io.InputStream input = exchange.getRequestBody()) {
                byte[] buffer = new byte[128]; int n;
                while ((n = input.read(buffer)) != -1) bytes.write(buffer, 0, n);
            }
            received.set(bytes.toByteArray());
            contentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
            exchange.sendResponseHeaders(401, expected.length);
            try (java.io.OutputStream output = exchange.getResponseBody()) { output.write(expected); }
        });
        server.start();
        try {
            Map.Entry<Integer, byte[]> response = transport(Duration.ofSeconds(2), 1024)
                    .send("http://127.0.0.1:" + server.getAddress().getPort() + "/test", "POST",
                            Collections8.map("Content-Type", "application/json"), expected);
            assertEquals(401, response.getKey().intValue());
            assertArrayEquals(expected, response.getValue());
            assertArrayEquals(expected, received.get());
            assertEquals("application/json", contentType.get());
        } finally { server.stop(0); }
    }

    @Test
    void doesNotFollowRedirectsOrReadUnboundedBodies() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicInteger forwarded = new AtomicInteger();
        server.createContext("/redirect", exchange -> {
            exchange.getResponseHeaders().set("Location", "/target");
            exchange.getResponseHeaders().set("Connection", "close");
            exchange.sendResponseHeaders(302, -1); exchange.close();
        });
        server.createContext("/target", exchange -> { forwarded.incrementAndGet(); exchange.sendResponseHeaders(200, -1); exchange.close(); });
        server.createContext("/large", exchange -> {
            byte[] bytes = new byte[1024]; exchange.sendResponseHeaders(200, bytes.length);
            try (java.io.OutputStream output = exchange.getResponseBody()) { output.write(bytes); }
        });
        server.start();
        try {
            Client.HttpClientTransport transport = transport(Duration.ofSeconds(2), 16);
            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            assertEquals(302, transport.send(base + "/redirect", "GET", Collections8.map(), null).getKey().intValue());
            assertEquals(0, forwarded.get());
            assertThrows(JoogopayException.ResponseTooLarge.class, () -> transport.send(base + "/large", "GET", Collections8.map(), null));
        } finally { server.stop(0); }
    }

    @Test
    void connectionFailureIsUnknownOutcomeAndInvalidTimeoutIsConfigurationError() throws Exception {
        java.net.ServerSocket socket = new java.net.ServerSocket(0, 0, java.net.InetAddress.getByName("127.0.0.1"));
        int port = socket.getLocalPort(); socket.close();
        assertThrows(JoogopayException.Transport.class, () -> transport(Duration.ofSeconds(1), 16)
                .send("http://127.0.0.1:" + port + "/test", "GET", Collections8.map(), null));
        assertThrows(JoogopayException.Config.class, () -> transport(Duration.ZERO, 16));
    }
    @Test
    void timesOutAndNeverRetriesAPost() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch stopped = new java.util.concurrent.CountDownLatch(1);
        AtomicInteger requests = new AtomicInteger();
        server.createContext("/drop", exchange -> { requests.incrementAndGet(); exchange.close(); });
        server.createContext("/wait", exchange -> {
            try { release.await(); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            finally { exchange.close(); stopped.countDown(); }
        });
        server.start();
        try {
            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            Client.HttpClientTransport transport = transport(Duration.ofMillis(150), 1024);
            assertThrows(JoogopayException.Transport.class, () -> transport.send(base + "/drop", "POST", Collections8.map(), new byte[]{1}));
            assertEquals(1, requests.get());
            assertThrows(JoogopayException.Transport.class, () -> transport.send(base + "/wait", "GET", Collections8.map(), null));
        } finally {
            release.countDown();
            server.stop(0);
            assertTrue(stopped.await(2, java.util.concurrent.TimeUnit.SECONDS), "handler must exit after timeout");
        }
    }

    @Test
    void honorsJvmProxyProperties() throws Exception {
        HttpServer proxy = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicInteger proxied = new AtomicInteger();
        proxy.createContext("/", exchange -> {
            proxied.incrementAndGet();
            byte[] body = "proxy".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (java.io.OutputStream output = exchange.getResponseBody()) { output.write(body); }
        });
        String host = System.getProperty("http.proxyHost");
        String port = System.getProperty("http.proxyPort");
        String exclusions = System.getProperty("http.nonProxyHosts");
        proxy.start();
        try {
            System.setProperty("http.proxyHost", "127.0.0.1");
            System.setProperty("http.proxyPort", Integer.toString(proxy.getAddress().getPort()));
            System.clearProperty("http.nonProxyHosts");
            Map.Entry<Integer, byte[]> response = transport(Duration.ofSeconds(2), 1024)
                    .send("http://unresolved.example/request", "GET", Collections8.map(), null);
            assertEquals("proxy", new String(response.getValue(), StandardCharsets.UTF_8));
            assertEquals(1, proxied.get());
        } finally {
            restore("http.proxyHost", host);
            restore("http.proxyPort", port);
            restore("http.nonProxyHosts", exclusions);
            proxy.stop(0);
        }
    }

    private static void restore(String name, String value) {
        if (value == null) System.clearProperty(name); else System.setProperty(name, value);
    }

    @Test
    void defaultPoolAllowsTwelveConcurrentRequests() throws Exception {
        checkPoolConcurrency(12, Client.DEFAULT_MAX_CONNECTIONS, false);
    }

    @Test
    void configuredPoolBoundsConcurrency() throws Exception {
        checkPoolConcurrency(2, 2, true);
        assertThrows(JoogopayException.Config.class,
                () -> new Client.HttpClientTransport(Duration.ofSeconds(2), 1024, 0));
    }

    private void checkPoolConcurrency(int concurrent, int limit, boolean checkWaiting) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        java.util.concurrent.ExecutorService handlers = java.util.concurrent.Executors.newFixedThreadPool(concurrent + 1);
        java.util.concurrent.ExecutorService callers = java.util.concurrent.Executors.newFixedThreadPool(concurrent + 1);
        java.util.concurrent.CountDownLatch entered = new java.util.concurrent.CountDownLatch(concurrent);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        AtomicInteger received = new AtomicInteger();
        server.setExecutor(handlers);
        server.createContext("/", exchange -> {
            received.incrementAndGet();
            entered.countDown();
            try {
                release.await();
                exchange.sendResponseHeaders(200, 1);
                try (java.io.OutputStream output = exchange.getResponseBody()) { output.write(1); }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally { exchange.close(); }
        });
        Client.HttpClientTransport client = checkWaiting
                ? new Client.HttpClientTransport(Duration.ofSeconds(5), 1024, limit)
                : new Client.HttpClientTransport(Duration.ofSeconds(5), 1024);
        transports.add(client);
        java.util.List<java.util.concurrent.Future<Integer>> requests = new java.util.ArrayList<>();
        server.start();
        try {
            String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/";
            java.util.concurrent.Callable<Integer> send = () -> client.send(url, "GET", Collections8.map(), null).getKey();
            for (int i = 0; i < concurrent; i++) requests.add(callers.submit(send));
            assertTrue(entered.await(3, java.util.concurrent.TimeUnit.SECONDS), "all requests must reach the server concurrently");
            if (checkWaiting) {
                java.util.concurrent.Future<Integer> waiting = callers.submit(send);
                requests.add(waiting);
                assertThrows(java.util.concurrent.TimeoutException.class,
                        () -> waiting.get(150, java.util.concurrent.TimeUnit.MILLISECONDS));
                assertEquals(concurrent, received.get(), "excess request must wait for a pool slot");
            }
            release.countDown();
            for (java.util.concurrent.Future<Integer> request : requests) {
                assertEquals(200, request.get(3, java.util.concurrent.TimeUnit.SECONDS).intValue());
            }
        } finally {
            release.countDown();
            client.close();
            server.stop(0);
            callers.shutdownNow();
            handlers.shutdownNow();
            assertTrue(callers.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS));
            assertTrue(handlers.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS));
        }
    }

    @Test
    void reusesConnectionsAndRejectsRequestsAfterClose() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        java.util.Set<Integer> ports = java.util.Collections.synchronizedSet(new java.util.HashSet<Integer>());
        server.createContext("/", exchange -> {
            ports.add(exchange.getRemoteAddress().getPort());
            exchange.sendResponseHeaders(200, 1);
            try (java.io.OutputStream output = exchange.getResponseBody()) { output.write(1); }
        });
        server.start();
        Client.HttpClientTransport client = transport(Duration.ofSeconds(2), 1024);
        String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/";
        try {
            client.send(url, "GET", Collections8.map(), null);
            client.send(url, "GET", Collections8.map(), null);
            assertEquals(1, ports.size(), "requests must reuse the same TCP connection");
            client.close();
            assertThrows(JoogopayException.Request.class, () -> client.send(url, "GET", Collections8.map(), null));
            Client.HttpClientTransport unused = transport(Duration.ofSeconds(1), 32);
            unused.close(); unused.close();
        } finally { client.close(); server.stop(0); }
    }

    @Test
    void concurrentCloseCancelsAnActiveRequest() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        java.util.concurrent.CountDownLatch started = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch handlerStopped = new java.util.concurrent.CountDownLatch(1);
        server.createContext("/", exchange -> {
            started.countDown();
            try { release.await(); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            finally { exchange.close(); handlerStopped.countDown(); }
        });
        java.util.concurrent.ExecutorService workers = java.util.concurrent.Executors.newFixedThreadPool(3);
        Client.HttpClientTransport client = transport(Duration.ofSeconds(10), 1024);
        server.start();
        try {
            String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/";
            java.util.concurrent.Future<?> request = workers.submit(() -> {
                assertThrows(JoogopayException.Transport.class, () -> client.send(url, "GET", Collections8.map(), null));
            });
            assertTrue(started.await(2, java.util.concurrent.TimeUnit.SECONDS));
            java.util.concurrent.Future<?> first = workers.submit(client::close);
            java.util.concurrent.Future<?> second = workers.submit(client::close);
            first.get(3, java.util.concurrent.TimeUnit.SECONDS);
            second.get(3, java.util.concurrent.TimeUnit.SECONDS);
            request.get(3, java.util.concurrent.TimeUnit.SECONDS);
        } finally {
            release.countDown();
            client.close();
            server.stop(0);
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS));
            assertTrue(handlerStopped.await(2, java.util.concurrent.TimeUnit.SECONDS));
        }
    }

}
