package com.joogopay.sdk;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;

/**
 * Assertions against the shared protocol vectors under protocol/testdata.
 *
 * <p>The vectors are the common source of truth for every SDK. A failure here means the Java
 * implementation disagrees with the protocol; fix the SDK, not the vectors.
 */
class ProtocolVectorTest {

    private static final Path TESTDATA = Path.of("protocol", "testdata");
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Decoder B64 = Base64.getDecoder();

    private static JsonNode load(String rel) throws IOException {
        return MAPPER.readTree(Files.readAllBytes(TESTDATA.resolve(rel)));
    }

    /** Rebuilds the header map from expected.signatureBase so the test invents no data of its own. */
    private static Map<String, String> headersFromBase(String signatureBase) {
        var names = Map.of(
                "content-type", "Content-Type",
                "content-encryption", Protocol.HEADER_CONTENT_ENCRYPTION,
                "content-digest", Protocol.HEADER_CONTENT_DIGEST,
                "idempotency-key", Protocol.HEADER_IDEMPOTENCY_KEY,
                "merchant-access-key", Protocol.HEADER_MERCHANT_ACCESS_KEY,
                "webhook-event-id", Protocol.HEADER_WEBHOOK_EVENT_ID);
        var headers = new HashMap<String, String>();
        for (String line : signatureBase.split("\n")) {
            int idx = line.indexOf(": ");
            if (idx < 0) {
                continue;
            }
            String key = line.substring(1, idx - 1); // strip the surrounding quotes
            if (names.containsKey(key)) {
                headers.put(names.get(key), line.substring(idx + 2));
            }
        }
        return headers;
    }

    private void assertSignatureVector(String name, List<String> covered) throws IOException {
        JsonNode v = load(name);
        JsonNode input = v.get("input");
        JsonNode expected = v.get("expected");

        var params = new Protocol.SignatureParams(
                Protocol.SIGNATURE_LABEL_MERCHANT, covered,
                1787803200L, 1787803500L, input.get("nonce").asText(), "",
                Protocol.SIGNATURE_ALG_ED25519);

        String gotInput = Protocol.signatureInputHeader(params);
        assertEquals(expected.get("signatureInput").asText(), gotInput, "Signature-Input");
        assertFalse(gotInput.contains("keyid"), "merchant requests carry no keyid");

        byte[] base = Protocol.signatureBase(
                params,
                input.get("method").asText(),
                input.get("path").asText(),
                input.get("rawQuery").asText(),
                headersFromBase(expected.get("signatureBase").asText()));
        assertEquals(expected.get("signatureBase").asText(),
                new String(base, StandardCharsets.UTF_8), "signature base");

        // Ed25519 signatures are deterministic, so they compare byte for byte
        String signature = Protocol.signEd25519(
                B64.decode(v.get("key").get("merchantPrivateKeyBase64").asText()),
                Protocol.SIGNATURE_LABEL_MERCHANT, base);
        assertEquals(expected.get("signature").asText(), signature, "signature");

        Protocol.verifyEd25519(
                B64.decode(v.get("key").get("merchantPublicKeyBase64").asText()),
                base,
                Protocol.parseSignature(expected.get("signature").asText(),
                        Protocol.SIGNATURE_LABEL_MERCHANT));
    }

    @Test
    void readQuerySignatureVector() throws IOException {
        assertSignatureVector("signature/001-read-query.json", Protocol.MERCHANT_READ_COVERED);
    }

    @Test
    void writeEnvelopeSignatureVector() throws IOException {
        assertSignatureVector("signature/002-write-envelope.json", Protocol.MERCHANT_WRITE_COVERED);
    }

    @Test
    void unicodeRawQuerySignatureVector() throws IOException {
        assertSignatureVector(
                "signature/003-read-raw-query-unicode.json",
                Protocol.MERCHANT_READ_COVERED);
    }

    /**
     * The 32-byte seed and the 64-byte private key sign identically. libsodium and OpenSSL
     * hand merchants the seed while the vectors carry the 64-byte form, so the seed path is only
     * exercised by an explicit assertion.
     */
    private void assertSeedEqualsFullKey(String name, List<String> covered) throws IOException {
        JsonNode v = load(name);
        JsonNode input = v.get("input");
        JsonNode expected = v.get("expected");
        JsonNode key = v.get("key");

        byte[] seed = B64.decode(key.get("merchantPrivateKeySeedBase64").asText());
        byte[] full = B64.decode(key.get("merchantPrivateKeyBase64").asText());
        assertEquals(32, seed.length, "seed length");
        assertEquals(64, full.length, "full key length");
        assertArrayEquals(seed, Arrays.copyOf(full, 32), "seed is the first 32 bytes of the full key");

        var params = new Protocol.SignatureParams(
                Protocol.SIGNATURE_LABEL_MERCHANT, covered,
                1787803200L, 1787803500L, input.get("nonce").asText(), "",
                Protocol.SIGNATURE_ALG_ED25519);
        byte[] base = Protocol.signatureBase(
                params,
                input.get("method").asText(),
                input.get("path").asText(),
                input.get("rawQuery").asText(),
                headersFromBase(expected.get("signatureBase").asText()));

        for (byte[] privateKey : List.of(seed, full)) {
            assertEquals(expected.get("signature").asText(),
                    Protocol.signEd25519(privateKey, Protocol.SIGNATURE_LABEL_MERCHANT, base),
                    "both key forms produce the same signature");
        }
    }

    @Test
    void readQuerySeedPrivateKey() throws IOException {
        assertSeedEqualsFullKey("signature/001-read-query.json", Protocol.MERCHANT_READ_COVERED);
    }

    @Test
    void writeEnvelopeSeedPrivateKey() throws IOException {
        assertSeedEqualsFullKey("signature/002-write-envelope.json", Protocol.MERCHANT_WRITE_COVERED);
    }

    @Test
    void clientAcceptsSeedAndFullPrivateKey() throws IOException {
        JsonNode v = load("signature/001-read-query.json");
        JsonNode key = v.get("key");
        for (String privateKey : List.of(
                key.get("merchantPrivateKeySeedBase64").asText(),
                key.get("merchantPrivateKeyBase64").asText())) {
            Client.builder()
                    .baseUrl("https://api.example.com")
                    .accessKey(v.get("input").get("accessKey").asText())
                    .merchantPrivateKeyBase64(privateKey)
                    .platformBodyKeyId("bodykey_1")
                    .platformBodyPublicKeyBase64(
                            Base64.getEncoder().encodeToString(new byte[32]))
                    .platformWebhookPublicKeys(
                            Map.of("whk_1", key.get("merchantPublicKeyBase64").asText()))
                    .build();
        }
    }

    @Test
    void signatureInputRoundTrip() throws IOException {
        JsonNode v = load("signature/001-read-query.json");
        String want = v.get("expected").get("signatureInput").asText();
        var params = Protocol.parseMerchantReadSignatureInput(want);
        assertEquals(v.get("input").get("nonce").asText(), params.nonce());
        assertEquals("", params.keyId(), "merchant side carries no keyId");
        assertEquals(want, Protocol.signatureInputHeader(params));
    }

    @Test
    void merchantSignatureInputRejectsKeyId() throws IOException {
        String tampered = load("signature/001-read-query.json")
                .get("expected").get("signatureInput").asText()
                .replace(";alg=\"ed25519\"", ";keyid=\"mkey_x\";alg=\"ed25519\"");
        assertThrows(JoogopayException.InvalidHeader.class,
                () -> Protocol.parseMerchantReadSignatureInput(tampered));
    }

    @Test
    void bodyEnvelopeOpensVectorCiphertext() throws IOException {
        JsonNode v = load("bodycrypt/001-sealed-box.json");
        byte[] wire = MAPPER.writeValueAsBytes(v.get("envelope"));

        assertEquals(v.get("keyId").asText(), Protocol.peekBodyEnvelopeKeyId(wire));

        var opened = Protocol.openBodyEnvelope(
                wire,
                B64.decode(v.get("platformBodyPublicKeyBase64").asText()),
                B64.decode(v.get("platformBodyPrivateKeyBase64").asText()));
        assertArrayEquals(B64.decode(v.get("plaintextBase64").asText()), opened.getKey());
        assertEquals(v.get("keyId").asText(), opened.getValue());

        assertThrows(JoogopayException.InvalidEnvelope.class,
                () -> Protocol.openBodyEnvelope(wire, new byte[32], new byte[32]));
    }

    @Test
    void bodyEnvelopeRoundTrips() throws IOException {
        JsonNode v = load("bodycrypt/001-sealed-box.json");
        byte[] plaintext = B64.decode(v.get("plaintextBase64").asText());

        byte[] wire = Protocol.sealBodyEnvelope(
                plaintext,
                B64.decode(v.get("platformBodyPublicKeyBase64").asText()),
                v.get("keyId").asText());
        var envelope = Protocol.decodeBodyEnvelope(wire);
        assertEquals(1, envelope.version());
        assertEquals(Protocol.CONTENT_ENCRYPTION, envelope.alg());
        assertEquals(v.get("keyId").asText(), envelope.keyId());

        var opened = Protocol.openBodyEnvelope(
                wire,
                B64.decode(v.get("platformBodyPublicKeyBase64").asText()),
                B64.decode(v.get("platformBodyPrivateKeyBase64").asText()));
        assertArrayEquals(plaintext, opened.getKey());
    }

    @Test
    void bodyEnvelopeRejectsDriftAndExtraFields() throws IOException {
        JsonNode v = load("bodycrypt/001-sealed-box.json");
        var wrongAlg = ((com.fasterxml.jackson.databind.node.ObjectNode) v.get("envelope")).deepCopy();
        wrongAlg.put("alg", "aes-gcm");
        assertThrows(JoogopayException.InvalidEnvelope.class,
                () -> Protocol.decodeBodyEnvelope(MAPPER.writeValueAsBytes(wrongAlg)));

        var extra = ((com.fasterxml.jackson.databind.node.ObjectNode) v.get("envelope")).deepCopy();
        extra.put("unexpected", "x");
        assertThrows(JoogopayException.InvalidEnvelope.class,
                () -> Protocol.decodeBodyEnvelope(MAPPER.writeValueAsBytes(extra)));
    }

    @Test
    void emptyObjectPostVector() throws IOException {
        JsonNode v = load("empty-object-post/001-empty-object.json");
        byte[] wire = MAPPER.writeValueAsBytes(v.get("envelope"));
        JsonNode bodyKey = v.get("platformBodyKey");
        JsonNode input = v.get("input");
        JsonNode expected = v.get("expected");

        assertEquals("{}", v.get("plaintext").asText());
        assertEquals(expected.get("contentDigest").asText(), Protocol.contentDigestSha256(wire));
        var opened = Protocol.openBodyEnvelope(
                wire,
                B64.decode(bodyKey.get("publicKeyBase64").asText()),
                B64.decode(bodyKey.get("privateKeyBase64").asText()));
        assertEquals("{}", new String(opened.getKey(), StandardCharsets.UTF_8));
        assertEquals(bodyKey.get("keyId").asText(), opened.getValue());

        var params = new Protocol.SignatureParams(
                Protocol.SIGNATURE_LABEL_MERCHANT, Protocol.MERCHANT_WRITE_COVERED,
                1787803200L, 1787803500L, input.get("nonce").asText(), "",
                Protocol.SIGNATURE_ALG_ED25519);
        assertEquals(expected.get("signatureInput").asText(),
                Protocol.signatureInputHeader(params));
        byte[] base = Protocol.signatureBase(
                params,
                input.get("method").asText(), input.get("path").asText(),
                input.get("rawQuery").asText(),
                headersFromBase(expected.get("signatureBase").asText()));
        assertEquals(expected.get("signatureBase").asText(),
                new String(base, StandardCharsets.UTF_8));
        assertEquals(expected.get("signature").asText(), Protocol.signEd25519(
                B64.decode(v.get("merchantKey").get("merchantPrivateKeyBase64").asText()),
                Protocol.SIGNATURE_LABEL_MERCHANT, base));

        assertThrows(JoogopayException.InvalidEnvelope.class,
                () -> Protocol.sealBodyEnvelope(
                        new byte[0], B64.decode(bodyKey.get("publicKeyBase64").asText()),
                        bodyKey.get("keyId").asText()));
    }

    @Test
    void webhookVector() throws IOException {
        JsonNode v = load("webhook/001-payment-succeeded.json");
        byte[] body = v.get("body").asText().getBytes(StandardCharsets.UTF_8);
        var headers = new HashMap<String, String>();
        v.get("headers").fields().forEachRemaining(e -> headers.put(e.getKey(), e.getValue().asText()));

        assertEquals(headers.get("Content-Digest"), Protocol.contentDigestSha256(body));
        assertTrue(Protocol.verifyContentDigest(body, headers.get("Content-Digest")));

        var params = Protocol.parsePlatformSignatureInput(headers.get("Signature-Input"));
        assertEquals(v.get("key").get("platformWebhookKeyId").asText(), params.keyId(),
                "platform side keeps keyId");

        JsonNode input = v.get("input");
        byte[] base = Protocol.signatureBase(params,
                input.get("method").asText(), input.get("path").asText(),
                input.get("rawQuery").asText(), headers);
        assertEquals(v.get("expected").get("signatureBase").asText(),
                new String(base, StandardCharsets.UTF_8), "webhook signature base");

        Protocol.verifyEd25519(
                B64.decode(v.get("key").get("platformWebhookPublicKeyBase64").asText()),
                base,
                Protocol.parseSignature(headers.get("Signature"), Protocol.SIGNATURE_LABEL_PLATFORM));
        assertThrows(JoogopayException.InvalidSignature.class,
                () -> Protocol.verifyEd25519(
                        new byte[32],
                        base,
                        Protocol.parseSignature(headers.get("Signature"),
                                Protocol.SIGNATURE_LABEL_PLATFORM)));

        Protocol.validateWebhookEventId(headers.get("Webhook-Event-Id"));
        assertEquals(headers.get("Webhook-Event-Id"),
                MAPPER.readTree(v.get("body").asText()).get("eventId").asText());
    }

    @Test
    void webhookRejectsTamperedAmount() throws IOException {
        JsonNode v = load("webhook/001-payment-succeeded.json");
        var headers = new HashMap<String, String>();
        v.get("headers").fields().forEachRemaining(e -> headers.put(e.getKey(), e.getValue().asText()));
        var params = Protocol.parsePlatformSignatureInput(headers.get("Signature-Input"));

        byte[] tampered = v.get("body").asText().replace("\"100.50\"", "\"999.00\"")
                .getBytes(StandardCharsets.UTF_8);
        assertFalse(Protocol.verifyContentDigest(tampered, headers.get("Content-Digest")));

        var tamperedHeaders = new HashMap<>(headers);
        tamperedHeaders.put("Content-Digest", Protocol.contentDigestSha256(tampered));
        JsonNode input = v.get("input");
        byte[] base = Protocol.signatureBase(params,
                input.get("method").asText(), input.get("path").asText(),
                input.get("rawQuery").asText(), tamperedHeaders);

        assertThrows(JoogopayException.InvalidSignature.class, () -> Protocol.verifyEd25519(
                B64.decode(v.get("key").get("platformWebhookPublicKeyBase64").asText()),
                base,
                Protocol.parseSignature(headers.get("Signature"), Protocol.SIGNATURE_LABEL_PLATFORM)));
    }

    @Test
    void uuidV4Rules() {
        assertTrue(Protocol.validUuidV4("b7754a6c-4a9c-4cf0-b77f-6f2d4b7e5f5a"));
        assertTrue(Protocol.validUuidV4(Protocol.newNonce()));
        assertFalse(Protocol.validUuidV4("B7754A6C-4A9C-4CF0-B77F-6F2D4B7E5F5A"), "must be lowercase");
        assertFalse(Protocol.validUuidV4("b7754a6c-4a9c-1cf0-b77f-6f2d4b7e5f5a"), "version nibble must be 4");
        assertFalse(Protocol.validUuidV4("b7754a6c-4a9c-4cf0-c77f-6f2d4b7e5f5a"), "variant must be 8/9/a/b");
    }

    @Test
    void webhookEventIdRules() {
        Protocol.validateWebhookEventId("evt_00000000000000000000000001");
        for (String bad : List.of("evt_0000", "xxx_00000000000000000000000001",
                "evt_0000000000000000000000000I")) {
            assertThrows(JoogopayException.InvalidHeader.class,
                    () -> Protocol.validateWebhookEventId(bad), bad);
        }
    }

    @Test
    void readQueryWhitelist() {
        Protocol.validateMerchantReadQuery("orderNo=P202608270001");
        Protocol.validateMerchantReadQuery("currency=BRL&payMethod=PIX");
        for (String bad : List.of("secret=1", "orderNo=", "orderNo=a&orderNo=b")) {
            assertThrows(JoogopayException.InvalidHeader.class,
                    () -> Protocol.validateMerchantReadQuery(bad), bad);
        }
    }

    @Test
    void freshnessWindow() {
        var params = Protocol.newMerchantReadSignatureParams(Protocol.newNonce(), 1787803200L);
        assertEquals(Protocol.MAX_SIGNATURE_LIFETIME, params.expires() - params.created());
        Protocol.validateFreshness(params, 1787803200L);
        Protocol.validateFreshness(params, 1787803500L);
        assertThrows(JoogopayException.ExpiredSignature.class,
                () -> Protocol.validateFreshness(params, 1787803501L));
        assertThrows(JoogopayException.ExpiredSignature.class,
                () -> Protocol.validateFreshness(params,
                        1787803200L - Protocol.MAX_SIGNATURE_LIFETIME - 1));
    }
}
