package com.joogopay.sdk;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.time.Duration;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;

/**
 * Client tests: wire shape, response vectors, the webhook path end to end, and config validation.
 *
 * <p>An injected Transport captures what the SDK actually sends: a POST carries no query, its
 * body is a sealed box envelope that the platform private key opens, Content-Digest covers the
 * envelope, and a GET has neither body nor idempotency key.
 */
class ClientTest {

    private static final Path TESTDATA = java.nio.file.Paths.get("protocol", "testdata");
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Decoder B64 = Base64.getDecoder();

    private static JsonNode load(String rel) throws IOException {
        return MAPPER.readTree(Files.readAllBytes(TESTDATA.resolve(rel)));
    }

    private static final class Captured {
        String url;
        String method;
        Map<String, String> headers = Collections8.map();
        byte[] body;
    }

    private Client.Transport transport(Captured captured, int status, byte[] responseBody) {
        return (url, method, headers, body) -> {
            captured.url = url;
            captured.method = method;
            captured.headers = new HashMap<>();
            headers.forEach((k, v) -> captured.headers.put(k.toLowerCase(Locale.ROOT), v));
            captured.body = body;
            return Collections8.entry(status, responseBody);
        };
    }

    private Client.Builder baseBuilder() throws IOException {
        JsonNode sig = load("signature/001-read-query.json");
        JsonNode body = load("bodycrypt/001-sealed-box.json");
        JsonNode hook = load("webhook/001-payment-succeeded.json");
        return Client.builder()
                .baseUrl("https://api.example.com")
                .accessKey("mak_live_test")
                .merchantPrivateKeyBase64(sig.get("key").get("merchantPrivateKeyBase64").asText())
                .platformBodyKeyId(body.get("keyId").asText())
                .platformBodyPublicKeyBase64(body.get("platformBodyPublicKeyBase64").asText())
                .platformWebhookPublicKeys(Collections8.map(
                        hook.get("key").get("platformWebhookKeyId").asText(),
                        hook.get("key").get("platformWebhookPublicKeyBase64").asText()));
    }

    private static byte[] envelopeJson(String data) {
        return ("{\"code\":200,\"msg\":\"OK\",\"data\":" + data + "}")
                .getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void transportFailureIsTransportNotRequest() throws IOException {
        Client client = baseBuilder().baseUrl("https://127.0.0.1:9").timeout(Duration.ofSeconds(2)).build();
        JoogopayException e = assertThrows(JoogopayException.Transport.class, () -> client.getBalance("BRL"));
        assertFalse(e instanceof JoogopayException.Request);
    }

    /**
     * Rejecting the key happens before anything is sent, so it must land in the same class
     * as any other pre-send failure; a merchant reading Transport here would query an order
     * that was never created.
     */
    @Test
    void malformedIdempotencyKeyIsRequestAndNothingIsSent() throws IOException {
        Captured captured = new Captured();
        Client client = baseBuilder().transport(transport(captured, 200, new byte[0])).build();
        assertThrows(JoogopayException.Request.class, () -> client.createPayment(Collections8.map(
                "merchantOrderNo", "M1", "currency", "BRL", "amount", "1.00",
                "paymentMethod", Collections8.map("code", "PIX", "pix", Collections8.map("payerName", "X")),
                "webhookUrl", "https://m.example.com/w"), "my-key-123"));
        assertNull(captured.url, "nothing reached the server");
    }

    @Test
    void createPaymentWireShapeAndServerSideDecrypt() throws IOException {
        JsonNode bodyVector = load("bodycrypt/001-sealed-box.json");
        Captured captured = new Captured();
        Client client = baseBuilder()
                .transport(transport(captured, 200, envelopeJson(
                        "{\"orderNo\":\"ORD001\",\"status\":\"PENDING\",\"amount\":\"100.00\"}")))
                .build();

        HashMap<String, Object> request = new LinkedHashMap<String, Object>();
        request.put("merchantOrderNo", "M202608270001");
        request.put("currency", "BRL");
        request.put("amount", "100.00");
        request.put("paymentMethod", Collections8.map("code", "PIX"));
        request.put("webhookUrl", "https://merchant.example.com/webhook/payments");

        Map<String, Object> order = client.createPayment(request);
        assertEquals("ORD001", order.get("orderNo"));
        assertEquals("100.00", order.get("amount"), "amount is a decimal string");

        assertEquals("POST", captured.method);
        assertFalse(captured.url.contains("?"), "POST carries no query");
        assertEquals("application/json", captured.headers.get("content-type"));
        assertEquals(Protocol.CONTENT_ENCRYPTION, captured.headers.get("content-encryption"));
        assertTrue(Protocol.validUuidV4(captured.headers.get("idempotency-key")));
        assertEquals("mak_live_test", captured.headers.get("merchant-access-key"));
        assertTrue(captured.headers.get("signature-input").startsWith("merchant=("));
        assertFalse(captured.headers.get("signature-input").contains("keyid"),
                "merchant requests carry no keyId");
        assertTrue(captured.headers.get("signature").startsWith("merchant=:"));

        assertEquals(Protocol.contentDigestSha256(captured.body),
                captured.headers.get("content-digest"), "digest covers the envelope");
        Protocol.BodyEnvelope envelope = Protocol.decodeBodyEnvelope(captured.body);
        assertEquals(Protocol.CONTENT_ENCRYPTION, envelope.alg());
        assertEquals(bodyVector.get("keyId").asText(), envelope.keyId());

        // the platform private key opens the merchant's original JSON
        Map.Entry<byte[], String> opened = Protocol.openBodyEnvelope(
                captured.body,
                B64.decode(bodyVector.get("platformBodyPublicKeyBase64").asText()),
                B64.decode(bodyVector.get("platformBodyPrivateKeyBase64").asText()));
        assertEquals(bodyVector.get("keyId").asText(), opened.getValue());
        assertEquals(MAPPER.readTree(MAPPER.writeValueAsBytes(request)),
                MAPPER.readTree(opened.getKey()));
    }

    @Test
    void idempotencyKeyIsReusable() throws IOException {
        Captured captured = new Captured();
        Client client = baseBuilder()
                .transport(transport(captured, 200, envelopeJson("{}")))
                .build();
        String key = Protocol.newNonce();
        Map<String, Object> request = Collections8.map(
                "merchantOrderNo", "M1", "currency", "BRL", "amount", "1.00",
                "payoutMethod", Collections8.map("code", "PIX",
                        "pix", Collections8.map("keyType", "CPF", "key", "12345678901")),
                "webhookUrl", "https://m.example.com/w");

        client.createPayout(request, key);
        String first = captured.headers.get("idempotency-key");
        client.createPayout(request, key);
        assertEquals(key, first);
        assertEquals(key, captured.headers.get("idempotency-key"));
    }

    @Test
    void readWireShape() throws IOException {
        Captured captured = new Captured();
        Client client = baseBuilder()
                .transport(transport(captured, 200, envelopeJson("{\"orderNo\":\"ORD001\"}")))
                .build();
        client.queryPaymentByOrderNo("P202608270001");

        assertEquals("GET", captured.method);
        assertEquals("https://api.example.com/api/v1/payments?orderNo=P202608270001", captured.url);
        assertEquals(null, captured.body, "GET has no body");
        for (String absent : Collections8.list("content-type", "content-encryption", "content-digest",
                "idempotency-key")) {
            assertFalse(captured.headers.containsKey(absent), "GET must not send " + absent);
        }
        assertFalse(captured.headers.get("signature-input").contains("keyid"));
    }

    @Test
    void readRejectsBlankQuery() throws IOException {
        Client client = baseBuilder()
                .transport(transport(new Captured(), 200, envelopeJson("{}")))
                .build();
        assertThrows(JoogopayException.Request.class,
                () -> client.queryPaymentByOrderNo("   "));
    }

    @Test
    void balanceAndRateUseTargetPaths() throws IOException {
        Captured captured = new Captured();
        Client client = baseBuilder()
                .transport(transport(captured, 200, envelopeJson("{\"usdRate\":\"5.40\"}")))
                .build();

        client.getBalance("BRL");
        assertTrue(captured.url.contains("/api/v1/balances?"), "not the legacy /merchant/balance");

        Map<String, Object> rate = client.getUsdRate("BRL", "PIX");
        assertTrue(captured.url.contains("/api/v1/usd-rates?"), "not the legacy /payment/usdRate");
        assertEquals("5.40", rate.get("usdRate"));
    }

    @Test
    void receiptEscapesPathAndHasNoQuery() throws IOException {
        Captured captured = new Captured();
        Client client = baseBuilder()
                .transport(transport(captured, 200, envelopeJson("{\"amount\":\"100.00\"}")))
                .build();
        client.getPayoutReceipt("ORD/001");
        assertEquals("https://api.example.com/api/v1/payouts/ORD%2F001/receipt", captured.url);
        assertFalse(captured.url.contains("?"));
    }

    @Test
    void receiptRejectsEmptyOrderNo() throws IOException {
        Client client = baseBuilder()
                .transport(transport(new Captured(), 200, envelopeJson("{}")))
                .build();
        assertThrows(JoogopayException.Request.class, () -> client.getPayoutReceipt(""));
    }

    @Test
    void responseVectorSuccess() throws IOException {
        JsonNode v = load("responses/001-success-payment-order.json");
        Client client = baseBuilder()
                .transport(transport(new Captured(), v.get("httpStatus").asInt(),
                        MAPPER.writeValueAsBytes(v.get("body"))))
                .build();
        Map<String, Object> order = client.queryPaymentByOrderNo("ORD202605190001");
        assertEquals("ORD202605190001", order.get("orderNo"));
        assertEquals(Status.SUCCEEDED, order.get("status"));
        assertEquals(Collections8.map("name", "Maria Silva", "documentNumber", "01234567890"), order.get("payer"));
    }

    @Test
    void responseVectorApiError() throws IOException {
        JsonNode v = load("responses/002-api-error-order-not-found.json");
        Client client = baseBuilder()
                .transport(transport(new Captured(), v.get("httpStatus").asInt(),
                        MAPPER.writeValueAsBytes(v.get("body"))))
                .build();
        JoogopayException.Api error = assertThrows(JoogopayException.Api.class,
                () -> client.queryPaymentByOrderNo("missing"));
        JsonNode want = v.get("expectedFields");
        assertEquals(want.get("HTTPStatus").asInt(), error.httpStatus);
        assertEquals(want.get("Code").asInt(), error.code);
        assertEquals(want.get("Msg").asText(), error.msg);
        assertEquals(want.get("Message").asText(), error.apiMessage);
        assertEquals(want.get("TraceID").asText(), error.traceId);
    }

    @Test
    void responseVectorHttp200ButEnvelopeCodeNotOk() throws IOException {
        JsonNode v = load("responses/003-http-200-envcode-not-ok.json");
        Client client = baseBuilder()
                .transport(transport(new Captured(), v.get("httpStatus").asInt(),
                        MAPPER.writeValueAsBytes(v.get("body"))))
                .build();
        JoogopayException.Api error = assertThrows(JoogopayException.Api.class,
                () -> client.queryPaymentByOrderNo("drift"));
        assertEquals(200, error.httpStatus);
        assertEquals(12100099, error.code);
    }

    @Test
    void responseVectorNonJson() throws IOException {
        JsonNode v = load("responses/004-non-json-body.json");
        byte[] html = Files.readAllBytes(
                TESTDATA.resolve("responses").resolve(v.get("bodyFile").asText()));
        Client client = baseBuilder()
                .transport(transport(new Captured(), v.get("httpStatus").asInt(), html))
                .build();
        JoogopayException.Response error = assertThrows(JoogopayException.Response.class,
                () -> client.queryPaymentByOrderNo("boom"));
        assertEquals(v.get("expectedFields").get("HTTPStatus").asInt(), error.httpStatus);
    }

    // An order map with no orderNo would be recorded as a successful payout.
    @Test
    void successWithoutDataIsResponseFailure() throws IOException {
        Client client = baseBuilder()
                .transport(transport(new Captured(), 200,
                        "{\"code\":200,\"msg\":\"OK\",\"data\":null}".getBytes(StandardCharsets.UTF_8)))
                .build();
        assertThrows(JoogopayException.Response.class, () -> client.queryPaymentByOrderNo("P1"));
    }

    @Test
    void responseVectorAmountsAreDecimalStrings() throws IOException {
        try (java.util.stream.Stream<Path> paths = Files.list(TESTDATA.resolve("responses"))) {
            for (Path path : paths.filter(p -> p.toString().endsWith(".json")).collect(java.util.stream.Collectors.toList())) {
                JsonNode data = MAPPER.readTree(Files.readAllBytes(path)).path("body").path("data");
                if (!data.isObject()) {
                    continue;
                }
                for (String field : Status.MONEY_FIELDS) {
                    JsonNode value = data.get(field);
                    if (value != null && !value.isNull()) {
                        assertTrue(value.isTextual(),
                                path.getFileName() + ": " + field + "=" + value
                                        + " must be a decimal string");
                    }
                }
            }
        }
    }

    private Map<String, String> hookHeaders(JsonNode hook) {
        Map<String, String> headers = new HashMap<String, String>();
        hook.get("headers").fields()
                .forEachRemaining(e -> headers.put(e.getKey(), e.getValue().asText()));
        return headers;
    }

    @Test
    void parsePaymentWebhook() throws IOException {
        JsonNode hook = load("webhook/001-payment-succeeded.json");
        Client client = baseBuilder()
                .clock(() -> 1787803300L)
                .transport(transport(new Captured(), 200, envelopeJson("{}")))
                .build();
        JsonNode input = hook.get("input");
        Map<String, Object> payload = client.parsePaymentWebhook(input.get("method").asText(),
                input.get("path").asText(), hookHeaders(hook),
                hook.get("body").asText().getBytes(StandardCharsets.UTF_8),
                input.get("rawQuery").asText());
        assertEquals(hook.get("headers").get("Webhook-Event-Id").asText(), payload.get("eventId"));
        assertEquals("PAYMENT", payload.get("orderType"));
        assertEquals(Status.SUCCEEDED, payload.get("status"));
        assertEquals("100.50", payload.get("amount"));
        assertEquals("100.50", payload.get("paidAmount"));
        assertFalse(payload.containsKey("payer"));
    }

    @Test
    void parsePaymentWebhookPayer() throws IOException {
        JsonNode hook = load("webhook/002-payment-payer.json");
        Client client = baseBuilder()
                .clock(() -> 1787803300L)
                .platformWebhookPublicKeys(Collections8.map(
                        hook.get("key").get("platformWebhookKeyId").asText(),
                        hook.get("key").get("platformWebhookPublicKeyBase64").asText()))
                .transport(transport(new Captured(), 200, envelopeJson("{}")))
                .build();
        JsonNode input = hook.get("input");
        Map<String, Object> payload = client.parsePaymentWebhook(input.get("method").asText(),
                input.get("path").asText(), hookHeaders(hook),
                hook.get("body").asText().getBytes(StandardCharsets.UTF_8),
                input.get("rawQuery").asText());
        assertEquals(Collections8.map("name", "Maria Silva", "documentNumber", "01234567890"), payload.get("payer"));
        assertEquals("100.50", payload.get("amount"));
        assertEquals("100.50", payload.get("paidAmount"));
    }

    @Test
    void parsePayoutWebhookReceiverAndSender() throws IOException {
        JsonNode hook = load("webhook/001-payment-succeeded.json");
        JsonNode key = load("signature/001-read-query.json").get("key");
        Client client = baseBuilder()
                .clock(() -> 1787803300L)
                .platformWebhookPublicKeys(Collections8.map(
                        hook.get("key").get("platformWebhookKeyId").asText(),
                        key.get("merchantPublicKeyBase64").asText()))
                .transport(transport(new Captured(), 200, envelopeJson("{}")))
                .build();
        for (String receiverJson : Collections8.list(
                "", "null", "{}", "{\"name\":\"João Silva\"}",
                "{\"documentNumber\":\"01234567890\"}",
                "{\"name\":\"Maria Silva\",\"documentType\":\"CPF\",\"documentNumber\":\"01234567890\","
                        + "\"keyType\":\"PIX\",\"key\":\"pix-key\",\"bankCode\":\"00000000\",\"bankName\":\"Banco do Brasil\"}")) {
            com.fasterxml.jackson.databind.node.ObjectNode payload = MAPPER.createObjectNode();
            payload.put("eventId", hook.get("headers").get("Webhook-Event-Id").asText());
            payload.put("orderType", "PAYOUT");
            payload.put("orderNo", "PO1");
            payload.put("merchantOrderNo", "M1");
            payload.put("status", "SUCCEEDED");
            payload.put("currency", "BRL");
            payload.put("amount", "10.00");
            payload.put("channelTradeNo", "E2E1");
            if (!receiverJson.isEmpty()) {
                payload.set("receiver", MAPPER.readTree(receiverJson));
            }
            Map<String, String> sender = receiverJson.contains("bankCode") ? Collections8.map(
                    "name", "Sender Company", "documentType", "CNPJ", "documentNumber", "01234567000189",
                    "bankCode", "00000000", "bankName", "Source Bank", "bankBranch", "0001",
                    "accountNumber", "000123", "accountSuffix", "9") : null;
            if (sender != null) {
                payload.set("sender", MAPPER.valueToTree(sender));
            }
            byte[] body = MAPPER.writeValueAsBytes(payload);
            Map<String, String> headers = hookHeaders(hook);
            headers.put("Content-Digest", Protocol.contentDigestSha256(body));
            Protocol.SignatureParams params = Protocol.parsePlatformSignatureInput(headers.get("Signature-Input"));
            headers.put("Signature", Protocol.signEd25519(
                    B64.decode(key.get("merchantPrivateKeyBase64").asText()), Protocol.SIGNATURE_LABEL_PLATFORM,
                    Protocol.signatureBase(params, "POST", "/webhook/payouts", "", headers)));
            Map<String, Object> parsed = client.parsePayoutWebhook("POST", "/webhook/payouts", headers, body);
            assertEquals(!receiverJson.isEmpty(), parsed.containsKey("receiver"), receiverJson);
            assertEquals(receiverJson.isEmpty() ? null : MAPPER.readValue(receiverJson, Object.class),
                    parsed.get("receiver"), receiverJson);
            assertEquals("10.00", parsed.get("amount"));
            assertEquals("SUCCEEDED", parsed.get("status"));
            assertEquals("E2E1", parsed.get("channelTradeNo"));
            assertEquals(sender, parsed.get("sender"));

            if (sender != null) {
                com.fasterxml.jackson.databind.node.ObjectNode altered = payload.deepCopy();
                ((com.fasterxml.jackson.databind.node.ObjectNode) altered.get("sender"))
                        .put("accountNumber", "999123");
                byte[] tampered = MAPPER.writeValueAsBytes(altered);
                for (boolean refreshDigest : Collections8.list(false, true)) {
                    HashMap<String, String> tamperedHeaders = new HashMap<>(headers);
                    if (refreshDigest) {
                        tamperedHeaders.put("Content-Digest", Protocol.contentDigestSha256(tampered));
                    }
                    Class<? extends JoogopayException> expectedError = refreshDigest
                            ? JoogopayException.InvalidSignature.class : JoogopayException.Webhook.class;
                    assertThrows(expectedError,
                            () -> client.parsePayoutWebhook("POST", "/webhook/payouts", tamperedHeaders, tampered));
                }
            }

            if (payload.path("receiver").has("documentNumber")) {
                ((com.fasterxml.jackson.databind.node.ObjectNode) payload.get("receiver"))
                        .put("documentNumber", "11234567890");
                byte[] tampered = MAPPER.writeValueAsBytes(payload);
                for (boolean refreshDigest : Collections8.list(false, true)) {
                    HashMap<String, String> tamperedHeaders = new HashMap<>(headers);
                    if (refreshDigest) {
                        tamperedHeaders.put("Content-Digest", Protocol.contentDigestSha256(tampered));
                    }
                    Class<? extends JoogopayException> expectedError = refreshDigest
                            ? JoogopayException.InvalidSignature.class : JoogopayException.Webhook.class;
                    assertThrows(expectedError,
                            () -> client.parsePayoutWebhook("POST", "/webhook/payouts", tamperedHeaders, tampered),
                            "altered receiver.documentNumber, refreshed digest=" + refreshDigest);
                }
            }
        }
    }

    @Test
    void paymentWebhookRejectsAlteredPayer() throws IOException {
        JsonNode hook = load("webhook/002-payment-payer.json");
        Client client = baseBuilder()
                .clock(() -> 1787803300L)
                .platformWebhookPublicKeys(Collections8.map(
                        hook.get("key").get("platformWebhookKeyId").asText(),
                        hook.get("key").get("platformWebhookPublicKeyBase64").asText()))
                .transport(transport(new Captured(), 200, envelopeJson("{}")))
                .build();
        for (String field : Collections8.list("name", "documentNumber")) {
            for (boolean refreshDigest : Collections8.list(false, true)) {
                JsonNode payload = MAPPER.readTree(hook.get("body").asText());
                ((com.fasterxml.jackson.databind.node.ObjectNode) payload.get("payer"))
                        .put(field, field.equals("name") ? "Other Name" : "11234567890");
                byte[] body = MAPPER.writeValueAsBytes(payload);
                Map<String, String> headers = hookHeaders(hook);
                if (refreshDigest) {
                    headers.put("Content-Digest", Protocol.contentDigestSha256(body));
                }
                Class<? extends JoogopayException> expectedError = refreshDigest
                        ? JoogopayException.InvalidSignature.class : JoogopayException.Webhook.class;
                assertThrows(expectedError,
                        () -> client.parsePaymentWebhook(
                                hook.get("input").get("method").asText(),
                                hook.get("input").get("path").asText(), headers, body,
                                hook.get("input").get("rawQuery").asText()),
                        "altered payer." + field + ", refreshed digest=" + refreshDigest);
            }
        }
    }

    @Test
    void webhookRejectsUnknownKeyId() throws IOException {
        JsonNode hook = load("webhook/001-payment-succeeded.json");
        Client client = baseBuilder()
                .clock(() -> 1787803300L)
                .platformWebhookPublicKeys(Collections8.map("wk_other",
                        hook.get("key").get("platformWebhookPublicKeyBase64").asText()))
                .transport(transport(new Captured(), 200, envelopeJson("{}")))
                .build();
        JoogopayException.Webhook error = assertThrows(JoogopayException.Webhook.class,
                () -> client.parsePaymentWebhook(
                        hook.get("input").get("method").asText(),
                        hook.get("input").get("path").asText(), hookHeaders(hook),
                        hook.get("body").asText().getBytes(StandardCharsets.UTF_8),
                        hook.get("input").get("rawQuery").asText()));
        assertTrue(error.getMessage().contains("platform key not found"));
    }

    @Test
    void webhookRejectsExpiredSignature() throws IOException {
        JsonNode hook = load("webhook/001-payment-succeeded.json");
        Client client = baseBuilder()
                .clock(() -> 1787803501L)
                .transport(transport(new Captured(), 200, envelopeJson("{}")))
                .build();
        assertThrows(JoogopayException.ExpiredSignature.class,
                () -> client.parsePaymentWebhook(
                        hook.get("input").get("method").asText(),
                        hook.get("input").get("path").asText(), hookHeaders(hook),
                        hook.get("body").asText().getBytes(StandardCharsets.UTF_8),
                        hook.get("input").get("rawQuery").asText()));
    }

    @Test
    void webhookRejectsWrongOrderType() throws IOException {
        JsonNode hook = load("webhook/001-payment-succeeded.json");
        Client client = baseBuilder()
                .clock(() -> 1787803300L)
                .transport(transport(new Captured(), 200, envelopeJson("{}")))
                .build();
        assertThrows(JoogopayException.Webhook.class,
                () -> client.parsePayoutWebhook(
                        hook.get("input").get("method").asText(),
                        hook.get("input").get("path").asText(), hookHeaders(hook),
                        hook.get("body").asText().getBytes(StandardCharsets.UTF_8),
                        hook.get("input").get("rawQuery").asText()));
    }

    @Test
    void webhookRejectsEventIdMismatch() throws IOException {
        JsonNode hook = load("webhook/001-payment-succeeded.json");
        Map<String, String> headers = hookHeaders(hook);
        headers.put("Webhook-Event-Id", "evt_0000000000000000000000000Z");
        Client client = baseBuilder()
                .clock(() -> 1787803300L)
                .transport(transport(new Captured(), 200, envelopeJson("{}")))
                .build();
        assertThrows(JoogopayException.Webhook.class,
                () -> client.parsePaymentWebhook(
                        hook.get("input").get("method").asText(),
                        hook.get("input").get("path").asText(), headers,
                        hook.get("body").asText().getBytes(StandardCharsets.UTF_8),
                        hook.get("input").get("rawQuery").asText()));
    }

    @Test
    void configValidation() throws IOException {
        Map<String, Consumer<Client.Builder>> cases = new LinkedHashMap<>();
        cases.put("empty baseUrl", b -> b.baseUrl(""));
        cases.put("http baseUrl", b -> b.baseUrl("http://api.example.com"));
        cases.put("non-https baseUrl scheme", b -> b.baseUrl("ftp://api.example.com"));
        cases.put("baseUrl with a path", b -> b.baseUrl("https://api.example.com/api/v1"));
        cases.put("baseUrl is not a URL", b -> b.baseUrl("not-a-url"));
        cases.put("empty accessKey", b -> b.accessKey(""));
        cases.put("invalid merchant private key", b -> b.merchantPrivateKeyBase64("bm90LWEta2V5"));
        cases.put("empty platformBodyKeyId", b -> b.platformBodyKeyId(""));
        cases.put("platform body public key of the wrong length", b -> b.platformBodyPublicKeyBase64("c2hvcnQ="));
        cases.put("empty webhook key set", b -> b.platformWebhookPublicKeys(Collections8.map()));

        for (Map.Entry<String, Consumer<Client.Builder>> entry : cases.entrySet()) {
            Client.Builder builder = baseBuilder()
                    .transport(transport(new Captured(), 200, envelopeJson("{}")));
            entry.getValue().accept(builder);
            assertThrows(JoogopayException.Config.class, builder::build, entry.getKey());
        }
    }

    @Test
    void submitPaymentTradeNoIsPlainJsonAndUnsigned() throws IOException {
        Captured captured = new Captured();
        Client client = baseBuilder()
                .transport(transport(captured, 200,
                        envelopeJson("{\"status\":1,\"orderStatus\":\"PENDING\"}")))
                .build();

        Map<String, Object> got = client.submitPaymentTradeNo("P1", "UTR123");
        assertEquals(1, ((Number) got.get("status")).intValue());
        assertEquals("PENDING", got.get("orderStatus"));

        assertEquals("POST", captured.method);
        assertEquals("https://api.example.com/api/v1/payment/submitTradeNo", captured.url);
        assertEquals("application/json", captured.headers.get("content-type"));
        assertFalse(captured.headers.containsKey("signature"), "public endpoints are unsigned");
        assertFalse(captured.headers.containsKey("content-encryption"), "body is not encrypted");
        assertEquals("{\"orderNo\":\"P1\",\"tradeNo\":\"UTR123\"}",
                new String(captured.body, StandardCharsets.UTF_8));
    }

    /** A refusal is also HTTP 200 with code 200; no exception does not mean accepted. */
    @Test
    void submitPaymentTradeNoRefusalIsNotAnException() throws IOException {
        Captured captured = new Captured();
        Client client = baseBuilder()
                .transport(transport(captured, 200, envelopeJson(
                        "{\"status\":0,\"message\":\"too many requests, please retry later\"}")))
                .build();

        Map<String, Object> got = client.submitPaymentTradeNo("P1", "UTR123");
        assertEquals(0, ((Number) got.get("status")).intValue());
        assertTrue(String.valueOf(got.get("message")).contains("too many requests"));
    }

    @Test
    void submitPaymentTradeNoRequiresBothFields() throws IOException {
        Client client = baseBuilder().transport(transport(new Captured(), 200, envelopeJson("{}"))).build();
        for (String[] tc : Collections8.list(
                new String[] {"", "UTR"},
                new String[] {"P1", ""},
                new String[] {" ", "UTR"},
                new String[] {"P1", " "})) {
            assertThrows(JoogopayException.Request.class,
                    () -> client.submitPaymentTradeNo(tc[0], tc[1]));
        }
    }

    @Test
    void supplementPaymentIsSignedEncryptedPostWithOneLocator() throws IOException {
        JsonNode bodyVector = load("bodycrypt/001-sealed-box.json");
        Captured captured = new Captured();
        Client client = baseBuilder()
                .transport(transport(captured, 200, envelopeJson(
                        "{\"orderNo\":\"P1\",\"merchantOrderNo\":\"M1\",\"status\":\"PROCESSING\","
                                + "\"amount\":\"100.00\",\"currency\":\"INR\"}")))
                .build();

        HashMap<String, Object> byOrderNo = new HashMap<String, Object>();
        byOrderNo.put("orderNo", " P1 ");
        byOrderNo.put("tradeNo", " 123456789012 ");
        HashMap<String, Object> byMerchantOrderNo = new HashMap<String, Object>();
        byMerchantOrderNo.put("merchantOrderNo", "M1");
        byMerchantOrderNo.put("orderNo", " ");
        byMerchantOrderNo.put("tradeNo", "123456789012");

        for (Map.Entry<? extends Map<String, Object>, String> tc : Collections8.list(
                Collections8.entry(byOrderNo, "{\"orderNo\":\"P1\",\"tradeNo\":\"123456789012\"}"),
                Collections8.entry(byMerchantOrderNo, "{\"merchantOrderNo\":\"M1\",\"tradeNo\":\"123456789012\"}"))) {
            String key = Protocol.newNonce();
            Map<String, Object> order = client.supplementPayment(tc.getKey(), key);
            assertEquals("P1", order.get("orderNo"));
            assertEquals(Status.PROCESSING, order.get("status"));

            assertEquals("POST", captured.method);
            assertEquals("https://api.example.com/api/v1/payments/trade-no", captured.url);
            assertEquals(Protocol.CONTENT_ENCRYPTION, captured.headers.get("content-encryption"));
            assertEquals(key, captured.headers.get("idempotency-key"));
            assertEquals("mak_live_test", captured.headers.get("merchant-access-key"));
            assertTrue(captured.headers.get("signature").startsWith("merchant=:"));
            assertEquals(Protocol.contentDigestSha256(captured.body), captured.headers.get("content-digest"));
            Map.Entry<byte[], String> opened = Protocol.openBodyEnvelope(
                    captured.body,
                    B64.decode(bodyVector.get("platformBodyPublicKeyBase64").asText()),
                    B64.decode(bodyVector.get("platformBodyPrivateKeyBase64").asText()));
            assertEquals(MAPPER.readTree(tc.getValue()), MAPPER.readTree(opened.getKey()));
        }
    }

    @Test
    void supplementPaymentValidatesLocally() throws IOException {
        Captured captured = new Captured();
        Client client = baseBuilder().transport(transport(captured, 200, envelopeJson("{}"))).build();
        for (Map<String, Object> tc : Collections8.<Map<String, Object>>list(
                Collections8.map("orderNo", "P1"),
                Collections8.map("orderNo", "P1", "tradeNo", " "),
                Collections8.map("tradeNo", "123456789012"),
                Collections8.map("orderNo", "P1", "merchantOrderNo", "M1", "tradeNo", "123456789012"))) {
            assertThrows(JoogopayException.Request.class, () -> client.supplementPayment(tc),
                    tc.toString());
        }
        assertNull(captured.url, "nothing reached the server");
    }

    @Test
    void supplementPaymentChannelErrorIsApiException() throws IOException {
        Client client = baseBuilder()
                .transport(transport(new Captured(), 422, ("{\"code\":12100019,\"msg\":\"CHANNEL_ERROR\","
                        + "\"traceId\":\"trace-ch\",\"data\":{\"message\":\"channel did not accept the reference\"}}")
                        .getBytes(StandardCharsets.UTF_8)))
                .build();
        JoogopayException.Api error = assertThrows(JoogopayException.Api.class,
                () -> client.supplementPayment(Collections8.map("orderNo", "P1", "tradeNo", "123456789012")));
        assertEquals(422, error.httpStatus);
        assertEquals(12100019, error.code);
        assertEquals("CHANNEL_ERROR", error.msg);
        assertEquals("channel did not accept the reference", error.apiMessage);
    }

    @Test
    void addPaymentExtraInfoOmitsOptionalFields() throws IOException {
        Captured captured = new Captured();
        Client client = baseBuilder()
                .transport(transport(captured, 200, envelopeJson(
                        "{\"status\":1,\"paymentUrl\":\"https://h5.example/p/1\"}")))
                .build();

        Map<String, Object> got = client.addPaymentExtraInfo(
                "P1", "PK_JAZZCASH", Collections8.map("mobile", "03001234567"));
        assertEquals("https://h5.example/p/1", got.get("paymentUrl"));
        assertEquals("https://api.example.com/api/v1/payment/addExtraInfo", captured.url);
        assertEquals(
                "{\"orderNo\":\"P1\",\"payMethod\":\"PK_JAZZCASH\","
                        + "\"extra\":{\"mobile\":\"03001234567\"}}",
                new String(captured.body, StandardCharsets.UTF_8));

        client.addPaymentExtraInfo("P1", null, null);
        assertEquals("{\"orderNo\":\"P1\"}", new String(captured.body, StandardCharsets.UTF_8));

        assertThrows(JoogopayException.Request.class, () -> client.addPaymentExtraInfo(" ", null, null));
    }

    // Pre-flight validation. The rule table is generated; these tests guard how it is applied.
    // Half the cases assert acceptance: a wrongly rejected valid request can only be fixed by an
    // SDK release.

    private Client validatingClient() throws IOException {
        return baseBuilder().transport(transport(new Captured(), 200, envelopeJson("{}"))).build();
    }

    private static Map<String, Object> payReq(String currency, Map<String, Object> method) {
        return Collections8.map("merchantOrderNo", "M1", "currency", currency, "amount", "1.00",
                "paymentMethod", method, "webhookUrl", "https://m.example.com/w");
    }

    @Test
    void validateRejectsBadMethodShape() throws IOException {
        Client c = validatingClient();
        class Case {
            final String ccy, fragment; final Map<String, Object> method;
            Case(String ccy, Map<String, Object> method, String fragment) { this.ccy = ccy; this.method = method; this.fragment = fragment; }
            String ccy() { return ccy; }
            Map<String, Object> method() { return method; }
            String fragment() { return fragment; }
        }
        List<Case> cases = Collections8.list(
                new Case("BRL", Collections8.map(), "code is required"),
                new Case("PKR", Collections8.map("code", "PK_JAZZCASH",
                        "pkJazzcash", Collections8.map("mobile", "03001234567"),
                        "pkEasypaisa", Collections8.map("mobile", "03001234567")), "only one method extra"),
                new Case("PKR", Collections8.map("code", "PK_JAZZCASH",
                        "pkEasypaisa", Collections8.map("mobile", "03001234567")), "does not match code"),
                new Case("PKR", Collections8.map("code", "PH_GCASH",
                        "phGcash", Collections8.map("mobile", "09171234567")), "not available for this currency"),
                new Case("IDR", Collections8.map("code", "ID_VA", "idVa",
                        Collections8.map("accountName", "Budi", "email", "b@example.com", "mobile", "0812")),
                        "extra.bankCode"));
        for (Case tc : cases) {
            JoogopayException.Request ex = assertThrows(JoogopayException.Request.class,
                    () -> c.createPayment(payReq(tc.ccy(), tc.method())));
            assertTrue(ex.getMessage().contains(tc.fragment()),
                    "want '" + tc.fragment() + "' in: " + ex.getMessage());
        }
    }

    @Test
    void validateAllowsValidRequests() throws IOException {
        Client c = validatingClient();
        List<Map<String, Object>> ok = Collections8.list(
                // PKR / PHP pay-in has no required extra; omitting it entirely is valid
                payReq("PKR", Collections8.map("code", "PK_JAZZCASH")),
                payReq("PKR", Collections8.map("code", "PK_JAZZCASH",
                        "pkJazzcash", Collections8.map("mobile", "03001234567"))),
                payReq("PHP", Collections8.map("code", "PH_GCASH")),
                payReq("IDR", Collections8.map("code", "ID_VA", "idVa", Collections8.map(
                        "accountName", "Budi", "email", "b@example.com",
                        "mobile", "0812", "bankCode", "BCA"))),
                payReq("XYZ", Collections8.map("code", "WHATEVER")),  // unknown currency is not blocked
                payReq("BRL", Collections8.map("code", "PIX")));      // no code whitelist for this currency, so no rejection
        for (Map<String, Object> req : ok) {
            c.createPayment(req);
        }
    }

    /**
     * Required extras differ per method code within one currency; a flattened table would
     * wrongly block IN_UPI.
     */
    @Test
    void validateHandlesConditionalRequired() throws IOException {
        Client c = validatingClient();
        java.util.function.Function<Map<String, Object>, Map<String, Object>> payout =
                m -> Collections8.map("merchantOrderNo", "M1", "currency", "INR", "amount", "1.00",
                        "payoutMethod", m, "webhookUrl", "https://m.example.com/w");

        c.createPayout(payout.apply(Collections8.map("code", "IN_UPI", "inUpi", Collections8.map(
                "account", "mary@upi", "name", "Mary",
                "email", "m@example.com", "mobile", "9871476369"))));

        assertThrows(JoogopayException.Request.class,
                () -> c.createPayout(payout.apply(Collections8.map("code", "IN_IFSC", "inIfsc", Collections8.map(
                        "name", "Mary", "email", "m@example.com", "mobile", "9871476369")))));

        c.createPayout(payout.apply(Collections8.map("code", "IN_IFSC", "inIfsc", Collections8.map(
                "account", "123456789", "ifsc", "HDFC0001234", "name", "Mary",
                "email", "m@example.com", "mobile", "9871476369"))));
    }


    /** The five IDR wallet payouts are accepted under their own extra field and rejected under another's. */
    @Test
    void validateAcceptsIdrWalletPayouts() throws IOException {
        Client c = validatingClient();
        // accountNo is the wallet-registered phone number and receives the funds; mobile is a contact number.
        java.util.function.Function<String, Map<String, Object>> extra = wallet -> Collections8.map(
                "bankCode", wallet, "accountNo", "081234567890", "accountName", "Budi",
                "email", "b@example.com", "mobile", "089999999999");
        java.util.function.Function<Map<String, Object>, Map<String, Object>> payout =
                m -> Collections8.map("merchantOrderNo", "M1", "currency", "IDR", "amount", "10000",
                        "payoutMethod", m, "webhookUrl", "https://m.example.com/w");

        for (String[] w : new String[][] {{"ID_DANA", "idDana", "DANA"}, {"ID_OVO", "idOvo", "OVO"},
                {"ID_GOPAY", "idGopay", "GOPAY"}, {"ID_LINKAJA", "idLinkaja", "LINKAJA"},
                {"ID_SHOPEEPAY", "idShopeepay", "SHOPEEPAY"}}) {
            c.createPayout(payout.apply(Collections8.map("code", w[0], w[1], extra.apply(w[2]))));
        }

        JoogopayException.Request ex = assertThrows(JoogopayException.Request.class,
                () -> c.createPayout(payout.apply(Collections8.map("code", "ID_DANA", "idOvo", extra.apply("OVO")))));
        assertTrue(ex.getMessage().contains("does not match code"), ex.getMessage());

        // accountNo is required for wallets as well; mobile never stands in for it.
        HashMap<String, Object> noAccount = new java.util.HashMap<>(extra.apply("DANA"));
        noAccount.put("accountNo", "");
        JoogopayException.Request missing = assertThrows(JoogopayException.Request.class,
                () -> c.createPayout(payout.apply(Collections8.map("code", "ID_DANA", "idDana", noAccount))));
        assertTrue(missing.getMessage().contains("extra.accountNo"), missing.getMessage());
    }

    /** PH wallets: one code per wallet in both directions; bankCode only for the bank transfer. */
    @Test
    void validateAcceptsPhWalletPayouts() throws IOException {
        Client c = validatingClient();
        java.util.function.Supplier<Map<String, Object>> extra = () -> Collections8.map(
                "accountNo", "09171234567", "accountName", "Juan",
                "email", "j@example.com", "mobile", "09171234567");
        java.util.function.Function<Map<String, Object>, Map<String, Object>> payout =
                m -> Collections8.map("merchantOrderNo", "M1", "currency", "PHP", "amount", "100.00",
                        "payoutMethod", m, "webhookUrl", "https://m.example.com/w");

        for (String[] w : new String[][] {{"PH_GCASH", "phGcash"}, {"PH_MAYA", "phMaya"}}) {
            c.createPayout(payout.apply(Collections8.map("code", w[0], w[1], extra.get())));
        }

        // PH_DF_WALLET is kept for existing integrations; there bankCode names the wallet.
        for (String[] b : new String[][] {{"PH_DF_BANK", "phDfBank"}, {"PH_DF_WALLET", "phDfWallet"}}) {
            JoogopayException.Request ex = assertThrows(JoogopayException.Request.class,
                    () -> c.createPayout(payout.apply(Collections8.map("code", b[0], b[1], extra.get()))));
            assertTrue(ex.getMessage().contains("extra.bankCode"), ex.getMessage());
        }
    }
    // Top-level required fields and formats, from the shared validation vectors. A failure here
    // means the Java implementation disagrees with the protocol; fix the SDK, not the vectors.

    private static String validationFragment(JsonNode c) {
        switch (c.get("reason").asText()) {
            case "missing_required_field": return "required field is empty: " + c.get("field").asText();
            case "invalid_amount": return "amount must be";
            case "invalid_webhook_url": return "webhookUrl must be";
            default: throw new IllegalArgumentException("unknown reason " + c.get("reason"));
        }
    }

    @Test
    void validationVectors() throws IOException {
        Client c = validatingClient();
        Path dir = TESTDATA.resolve("validation");
        List<Path> files;
        try (java.util.stream.Stream<Path> stream = Files.list(dir)) {
            files = stream.filter(p -> p.toString().endsWith(".json")).sorted().collect(java.util.stream.Collectors.toList());
        }
        assertFalse(files.isEmpty(), "no validation vectors in " + dir);
        for (Path file : files) {
            JsonNode vector = MAPPER.readTree(Files.readAllBytes(file));
            boolean payment = "payment".equals(vector.get("direction").asText());
            for (JsonNode tc : vector.get("cases")) {
                String label = file.getFileName() + " / " + tc.get("name").asText();
                HashMap<String, Object> body = new HashMap<String, Object>(
                        MAPPER.convertValue(vector.get("base"), new TypeReference<Map<String, Object>>() {}));
                body.putAll(MAPPER.convertValue(tc.get("override"), new TypeReference<Map<String, Object>>() {}));
                Runnable call = () -> {
                    if (payment) {
                        c.createPayment(body);
                    } else {
                        c.createPayout(body);
                    }
                };
                if ("accept".equals(tc.get("expect").asText())) {
                    call.run();
                    continue;
                }
                JoogopayException.Request ex = assertThrows(JoogopayException.Request.class, call::run, label);
                String fragment = validationFragment(tc);
                assertTrue(ex.getMessage().contains(fragment),
                        label + ": want '" + fragment + "', got " + ex.getMessage());
            }
        }
    }

    @Test
    void receiptRejectsBlankAndTrimsOrderNo() throws IOException {
        Captured captured = new Captured();
        Client c = baseBuilder().transport(transport(captured, 200, envelopeJson("{}"))).build();
        for (String bad : Collections8.list("", "  ", "\t")) {
            assertThrows(JoogopayException.Request.class, () -> c.getPayoutReceipt(bad));
        }
        assertThrows(JoogopayException.Request.class, () -> c.getPayoutReceipt(null));
        c.getPayoutReceipt("  P202608270001 ");
        assertEquals("https://api.example.com/api/v1/payouts/P202608270001/receipt", captured.url);
    }
    @Test
    void arsPayoutPreservesOptionalNullableAddressesAndRejectsOtherTypes() throws IOException {
        Captured captured = new Captured();
        Client client = baseBuilder().transport(transport(captured, 200, envelopeJson("{}"))).build();
        JsonNode bodyKey = load("bodycrypt/001-sealed-box.json");
        Map<String, Object> extra = new HashMap<>(Collections8.map(
                "firstName", "Ana", "lastName", "Perez", "email", "ana@example.com", "phone", "1123456789",
                "documentType", "DNI", "documentNumber", "30123456",
                "accountNo", "0000003100012345678901", "accountType", "CBU"));
        java.util.function.Function<Map<String, Object>, Map<String, Object>> request = fields -> Collections8.map(
                "merchantOrderNo", "ars-address-001", "currency", "ARS", "amount", "1.00",
                "webhookUrl", "https://merchant.example.com/webhook",
                "payoutMethod", Collections8.map("code", "BANK_TRANSFER", "bankTransfer", fields));
        for (String accountType : Collections8.list("CBU", "CVU")) {
            Map<String, Object> recipient = new HashMap<>(extra);
            recipient.put("accountType", accountType);
            java.util.ArrayList<Map<String, Object>> accepted = new java.util.ArrayList<Map<String, Object>>();
            accepted.add(new HashMap<>(recipient));
            for (String address : new String[]{null, "", " Av Example 123 "}) {
                Map<String, Object> fields = new HashMap<>(recipient);
                fields.put("address", address);
                accepted.add(fields);
            }
            for (Map<String, Object> fields : accepted) {
                Map<String, Object> input = request.apply(fields);
                JsonNode expected = MAPPER.valueToTree(input);
                client.createPayout(input);
                Map.Entry<byte[], String> opened = Protocol.openBodyEnvelope(captured.body,
                        B64.decode(bodyKey.get("platformBodyPublicKeyBase64").asText()),
                        B64.decode(bodyKey.get("platformBodyPrivateKeyBase64").asText()));
                assertEquals(expected, MAPPER.readTree(opened.getKey()));
                assertEquals(expected, MAPPER.valueToTree(input), "caller input must remain unchanged");
            }
            byte[] lastBody = captured.body;
            for (Object address : new Object[]{1, false, Collections8.list(), Collections8.map()}) {
                Map<String, Object> invalid = new HashMap<>(recipient);
                invalid.put("address", address);
                JoogopayException.Request error = assertThrows(JoogopayException.Request.class,
                        () -> client.createPayout(request.apply(invalid)));
                assertTrue(error.getMessage().contains("extra.address"));
                assertTrue(captured.body == lastBody, "invalid address must fail before HTTP");
            }
            for (String field : recipient.keySet()) {
                java.util.ArrayList<Map<String, Object>> invalidValues = new java.util.ArrayList<Map<String, Object>>();
                Map<String, Object> missing = new HashMap<>(recipient);
                missing.remove(field);
                invalidValues.add(missing);
                for (String empty : new String[]{null, "", "  "}) {
                    Map<String, Object> invalid = new HashMap<>(recipient);
                    invalid.put(field, empty);
                    invalidValues.add(invalid);
                }
                for (Map<String, Object> invalid : invalidValues) {
                    JoogopayException.Request error = assertThrows(JoogopayException.Request.class,
                            () -> client.createPayout(request.apply(invalid)));
                    assertTrue(error.getMessage().contains("extra." + field));
                    assertTrue(captured.body == lastBody, field + " must fail before HTTP");
                }
            }
        }
    }

    @Test
    void usdWalletContract() throws Exception {
        JsonNode fixture = load("methods/001-usd-wallets.json");
        JsonNode bodyKey = load("bodycrypt/001-sealed-box.json");
        java.util.ArrayList<JsonNode> requests = new java.util.ArrayList<JsonNode>();
        requests.add(fixture.get("payment"));
        fixture.get("payouts").forEach(requests::add);
        for (JsonNode request : requests) {
            String methodField = request.has("paymentMethod") ? "paymentMethod" : "payoutMethod";
            JsonNode method = request.get(methodField);
            String branch = method.has("cashApp") ? "cashApp" : (method.has("paypal") ? "paypal" : "chime");
            Captured captured = new Captured();
            Client client = baseBuilder().transport(transport(captured, 200, envelopeJson("{}"))).build();
            java.util.function.Function<JsonNode, Object> create = value -> {
                Map<String, Object> map = MAPPER.convertValue(value, new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
                return methodField.equals("paymentMethod") ? client.createPayment(map) : client.createPayout(map);
            };
            create.apply(request);
            Map.Entry<byte[], String> opened = Protocol.openBodyEnvelope(captured.body,
                    B64.decode(bodyKey.get("platformBodyPublicKeyBase64").asText()),
                    B64.decode(bodyKey.get("platformBodyPrivateKeyBase64").asText()));
            assertEquals(request, MAPPER.readTree(opened.getKey()));
            byte[] lastBody = captured.body;
            for (String field : (Iterable<String>) () -> method.get(branch).fieldNames()) {
                for (String empty : new String[] {null, "", "  "}) {
                    com.fasterxml.jackson.databind.node.ObjectNode invalid = request.deepCopy();
                    ((com.fasterxml.jackson.databind.node.ObjectNode) invalid.get(methodField).get(branch)).put(field, empty);
                    assertThrows(JoogopayException.Request.class, () -> create.apply(invalid));
                    assertTrue(captured.body == lastBody, field + " must fail before HTTP");
                }
            }
            com.fasterxml.jackson.databind.node.ObjectNode formats = request.deepCopy();
            method.get(branch).fieldNames().forEachRemaining(field ->
                    ((com.fasterxml.jackson.databind.node.ObjectNode) formats.get(methodField).get(branch))
                            .put(field, "format-is-checked-by-gateway"));
            create.apply(formats);
        }
    }

    @Test
    void payoutRefundQueryAndSignedWebhook() throws IOException {
        JsonNode response = load("responses/005-payout-refunded.json");
        JsonNode hook = load("webhook/003-payout-refunded.json");
        Client client = baseBuilder().clock(() -> 1787803300L)
                .platformWebhookPublicKeys(Collections8.map(hook.get("key").get("platformWebhookKeyId").asText(),
                        hook.get("key").get("platformWebhookPublicKeyBase64").asText()))
                .transport(transport(new Captured(), 200, MAPPER.writeValueAsBytes(response.get("body"))))
                .build();
        Map<String, Object> order = client.queryPayoutByOrderNo("PO202609240001");
        JsonNode input = hook.get("input");
        Map<String, Object> payload = client.parsePayoutWebhook(input.get("method").asText(), input.get("path").asText(),
                hookHeaders(hook), hook.get("body").asText().getBytes(StandardCharsets.UTF_8), input.get("rawQuery").asText());
        for (Map<String, Object> result : Collections8.list(order, payload)) {
            assertEquals(Status.REFUNDED, result.get("status"));
            assertEquals("R202609240001", result.get("refundNo"));
            assertEquals("100.00", result.get("refundAmount"));
            assertEquals(1790208000000L, ((Number) result.get("refundTime")).longValue());
        }
    }

}
