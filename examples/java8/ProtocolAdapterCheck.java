import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;


public final class ProtocolAdapterCheck {

    static final String ACCESS_KEY = "mak_live_test";
    static final String MERCHANT_SEED = "ERERERERERERERERERERERERERERERERERERERERERE=";
    static final String MERCHANT_KEY_64 = "ERERERERERERERERERERERERERERERERERERERERERHQSrIydCu0qzoTaL1GFeTm0CJKtxoBa6+FIKMyyXeHNw==";
    static final String BODY_KEY_ID = "body_test_1";
    static final String BODY_PUBLIC = "ew1H2TQn+DERYHgcfHM/2J+IlwrvSQ2KoO4ZpMuKGxQ=";
    static final String BODY_PRIVATE = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=";
    static final String WEBHOOK_KEY_ID = "wk_test_1";
    static final String WEBHOOK_PUBLIC = "oJql9HpnWYAv+VX43C0qFKXJnSO+l/hkEn/5ODRVpPA=";
    static final long CREATED = 1787803200L;
    static final String NONCE = "b7754a6c-4a9c-4cf0-b77f-6f2d4b7e5f5a";
    static final String IDEMPOTENCY_KEY = "018fb9b4-95f3-4a47-8f08-27466f7d4c1d";
    static final String READ_SIGNATURE = "merchant=:H1IK1NGk7htlA/O3JZhndbDGkl/gB/a3Hw4wtlNGXoG+mHYvtSGUWBUs0fJOc0MpNrJ5KYGqnohDDXd9jAxYCg==:";
    static final String EMPTY_OBJECT_CIPHERTEXT = "cJNCfLPrdwPA1SZ2zlRZcTTCleOO3Uq6MUvcgKQK+EAzfODrnKQNQRQvklJoJH8AvVI=";
    static final String EMPTY_OBJECT_DIGEST = "sha-256=:gqerLWZham0+ixKxFepM6uwmfeHVjNonc2K8FnniuWI=:";
    static final String EMPTY_OBJECT_SIGNATURE = "merchant=:OX2sXBOrHfC6Jh0Dyhf202YrQbUwxK6iqQHnupIS3Vknp9SwioVugT4WewoSWLR0G2/yCxON0/utB43Ra4N8Dw==:";
    static final String SEALED_BOX_CIPHERTEXT = "4/P7Wrlz8Xro74MZefTrzvgPdtxbSwgW/flVInsOlE6wo9IRNfFL3yeHZC49nJYNxfCYUcBjN3fnkymHXfBwW1ySJT5yyBOVhSoqk0RPKcP4balb+NTMZ/aXrfaAs42naQpLB/btI1ISEKGfOAvF0mVgpSdKMQ==";
    static final String SEALED_BOX_PLAINTEXT_B64 = "eyJtZXJjaGFudE9yZGVyTm8iOiJNMjAyNjA4MjcwMDAxIiwiYW1vdW50IjoiMTAwLjUwIiwiY3VycmVuY3kiOiJCUkwifQ==";
    static final String WEBHOOK_BODY = "{\"eventId\":\"evt_00000000000000000000000001\",\"orderType\":\"PAYMENT\",\"orderNo\":\"P202608270001\","
            + "\"merchantOrderNo\":\"M202608270001\",\"status\":\"SUCCEEDED\",\"currency\":\"BRL\",\"amount\":\"100.50\",\"paidAmount\":\"100.50\"}";
    static final String WEBHOOK_DIGEST = "sha-256=:1bxiy7QF1KLU6+Jk7A57caRaycHHhfNvu8iYeMUm7ow=:";
    static final String WEBHOOK_SIGNATURE = "platform=:TLA+qU2lY8Ez0mUSayVbdg0h9Yce6dndROAlF21ToHbXpeY90aY1RSNowIkaX6oujwZDdt6aKh+2OAItmLWdAQ==:";
    static final String WEBHOOK_SIGNATURE_INPUT = "platform=(\"@method\" \"@path\" \"@query\" \"content-type\" \"content-digest\" \"webhook-event-id\");created=1787803200;expires=1787803500;nonce=\"b7754a6c-4a9c-4cf0-b77f-6f2d4b7e5f5a\";keyid=\"wk_test_1\";alg=\"ed25519\"";
    static final String WEBHOOK_EVENT_ID = "evt_00000000000000000000000001";

    private static int passed;


    interface WebhookVerifierFn {
        String verify(String path, String rawQuery, Map<String, String> headers, byte[] body, long now) throws Exception;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("java.version=" + System.getProperty("java.version")
                + " java.vendor=" + System.getProperty("java.vendor")
                + " bouncycastle=" + Paths.get(XSalsa20Engine.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getFileName());
        ProtocolAdapter auth = newAuth(MERCHANT_SEED);

        // signature/001-read-query.json
        ProtocolAdapter.SignedRequest read = auth.signRead("/api/v1/payments", "orderNo=P202608270001", CREATED, NONCE);
        expect("GET signature vector signature/001", read.headers.get("Signature"), READ_SIGNATURE);
        expect("GET Signature-Input vector", read.headers.get("Signature-Input"),
                "merchant=(\"@method\" \"@path\" \"@query\" \"merchant-access-key\");created=1787803200;expires=1787803500;nonce=\"b7754a6c-4a9c-4cf0-b77f-6f2d4b7e5f5a\";alg=\"ed25519\"");

        // empty-object-post/001-empty-object.json
        byte[] emptyObjectEnvelope = ("{\"version\":1,\"alg\":\"sealedbox-v1-x25519-xsalsa20poly1305\",\"keyId\":\"body_test_1\","
                + "\"ciphertext\":\"" + EMPTY_OBJECT_CIPHERTEXT + "\"}").getBytes(StandardCharsets.UTF_8);
        ProtocolAdapter.SignedRequest write = auth.signSealedWrite("/api/v1/payments", emptyObjectEnvelope, CREATED, NONCE, IDEMPOTENCY_KEY);
        expect("POST Content-Digest vector empty-object-post/001", write.headers.get("Content-Digest"), EMPTY_OBJECT_DIGEST);
        expect("POST signature vector empty-object-post/001", write.headers.get("Signature"), EMPTY_OBJECT_SIGNATURE);
        expect("64-byte private key signature",
                newAuth(MERCHANT_KEY_64).signSealedWrite("/api/v1/payments", emptyObjectEnvelope, CREATED, NONCE, IDEMPOTENCY_KEY).headers.get("Signature"),
                EMPTY_OBJECT_SIGNATURE);
        expect("PKCS#8 PEM signature",
                newAuth(pemFromSeed(MERCHANT_SEED)).signSealedWrite("/api/v1/payments", emptyObjectEnvelope, CREATED, NONCE, IDEMPOTENCY_KEY).headers.get("Signature"),
                EMPTY_OBJECT_SIGNATURE);

        expect("sealed box reference ciphertext",
                new String(sealedBoxOpen(b64(SEALED_BOX_CIPHERTEXT), b64(BODY_PUBLIC), b64(BODY_PRIVATE)), StandardCharsets.UTF_8),
                new String(b64(SEALED_BOX_PLAINTEXT_B64), StandardCharsets.UTF_8));
        expect("empty object envelope",
                new String(sealedBoxOpen(b64(EMPTY_OBJECT_CIPHERTEXT), b64(BODY_PUBLIC), b64(BODY_PRIVATE)), StandardCharsets.UTF_8), "{}");
        byte[] message = "{\"merchantOrderNo\":\"RT0001\",\"amount\":\"1.00\"}".getBytes(StandardCharsets.UTF_8);
        expect("seal/open round trip", new String(sealedBoxOpen(ProtocolAdapter.sealedBox(message, b64(BODY_PUBLIC)), b64(BODY_PUBLIC), b64(BODY_PRIVATE)), StandardCharsets.UTF_8),
                new String(message, StandardCharsets.UTF_8));

        final ProtocolAdapter verifier = auth;
        expect("signed webhook event id",
                auth.verifyWebhook("/webhook/payments", "tenant=main%2Fbr", vectorWebhookHeaders(), WEBHOOK_BODY.getBytes(StandardCharsets.UTF_8), CREATED).eventId,
                WEBHOOK_EVENT_ID);
        runWebhookContract("ProtocolAdapter", new WebhookVerifierFn() {
            public String verify(String path, String rawQuery, Map<String, String> headers, byte[] body, long now) {
                return verifier.verifyWebhook(path, rawQuery, headers, body, now).json;
            }
        });

        System.out.println("ALL " + passed + " CHECKS PASSED");
    }


    static void runWebhookContract(String label, WebhookVerifierFn fn) throws Exception {
        byte[] body = WEBHOOK_BODY.getBytes(StandardCharsets.UTF_8);
        expect(label + " webhook signature vector",
                fn.verify("/webhook/payments", "tenant=main%2Fbr", vectorWebhookHeaders(), body, CREATED), WEBHOOK_BODY);

        List<RejectCase> rejects = new ArrayList<RejectCase>();
        rejects.add(rejectCase("modified amount", null, null, WEBHOOK_BODY.replace("100.50\",\"paidAmount", "999.50\",\"paidAmount"), "tenant=main%2Fbr", CREATED));
        rejects.add(rejectCase("modified query", null, null, null, "tenant=main%2Fbr2", CREATED));
        rejects.add(rejectCase("expired", null, null, null, "tenant=main%2Fbr", CREATED + 301));
        rejects.add(rejectCase("created too far in future", null, null, null, "tenant=main%2Fbr", CREATED - 301));
        rejects.add(rejectCase("invalid lifetime", "Signature-Input", WEBHOOK_SIGNATURE_INPUT.replace("expires=1787803500", "expires=1787803200"), null, "tenant=main%2Fbr", CREATED));
        rejects.add(rejectCase("oversized timestamp", "Signature-Input", WEBHOOK_SIGNATURE_INPUT.replace("created=1787803200", "created=99999999999999999999999"), null, "tenant=main%2Fbr", CREATED));
        rejects.add(rejectCase("invalid signature Base64", "Signature", "platform=:A:", null, "tenant=main%2Fbr", CREATED));
        rejects.add(rejectCase("invalid signature length", "Signature", "platform=:AAAA:", null, "tenant=main%2Fbr", CREATED));
        rejects.add(rejectCase("missing Signature", "Signature", "", null, "tenant=main%2Fbr", CREATED));
        rejects.add(rejectCase("missing Signature-Input", "Signature-Input", "", null, "tenant=main%2Fbr", CREATED));
        rejects.add(rejectCase("missing covered component", "Signature-Input", WEBHOOK_SIGNATURE_INPUT.replace(" \"@query\"", ""), null, "tenant=main%2Fbr", CREATED));
        rejects.add(rejectCase("invalid nonce", "Signature-Input", WEBHOOK_SIGNATURE_INPUT.replace("b7754a6c-4a9c-4cf0-b77f-6f2d4b7e5f5a", "not-a-uuid"), null, "tenant=main%2Fbr", CREATED));
        rejects.add(rejectCase("duplicate parameter", "Signature-Input", WEBHOOK_SIGNATURE_INPUT + ";created=1787803200", null, "tenant=main%2Fbr", CREATED));
        rejects.add(rejectCase("unknown key id", "Signature-Input", WEBHOOK_SIGNATURE_INPUT.replace("wk_test_1", "wk_other"), null, "tenant=main%2Fbr", CREATED));
        rejects.add(rejectCase("unsupported algorithm", "Signature-Input", WEBHOOK_SIGNATURE_INPUT.replace("alg=\"ed25519\"", "alg=\"rsa-v1_5-sha256\""), null, "tenant=main%2Fbr", CREATED));
        rejects.add(rejectCase("Content-Type with charset", "Content-Type", "application/json; charset=utf-8", null, "tenant=main%2Fbr", CREATED));
        rejects.add(rejectCase("invalid event id", "Webhook-Event-Id", "evt_1", null, "tenant=main%2Fbr", CREATED));
        rejects.add(rejectCase("empty body", null, null, "", "tenant=main%2Fbr", CREATED));
        for (RejectCase c : rejects) {
            expectRejected(label + " rejected: " + c.name, fn, c.rawQuery, c.headers, c.body, c.now);
        }

        Map<String, String> duplicated = vectorWebhookHeaders();
        duplicated.put("signature", WEBHOOK_SIGNATURE);
        expectRejected(label + " rejected duplicate header name", fn, "tenant=main%2Fbr", duplicated, body, CREATED);

        Random random = new Random(20261028L);
        String alphabet = "\"();=:,+/\\ \t-_aZ09é";
        int mutations = 0;
        for (String name : vectorWebhookHeaders().keySet()) {
            for (int i = 0; i < 300; i++) {
                Map<String, String> headers = vectorWebhookHeaders();
                StringBuilder value = new StringBuilder(headers.get(name));
                int op = random.nextInt(3);
                int pos = value.length() == 0 ? 0 : random.nextInt(value.length());
                if (op == 0) {
                    value.setLength(pos);
                } else if (op == 1) {
                    value.insert(pos, alphabet.charAt(random.nextInt(alphabet.length())));
                } else if (value.length() > 0) {
                    value.setCharAt(pos, alphabet.charAt(random.nextInt(alphabet.length())));
                }
                headers.put(name, value.toString());
                try {
                    fn.verify("/webhook/payments", "tenant=main%2Fbr", headers, body, CREATED);
                } catch (SecurityException expected) {
                } catch (Exception other) {
                    throw new AssertionError(label + " mutation " + name + "=" + value + " threw " + other);
                }
                mutations++;
            }
        }
        passed++;
        System.out.println("[PASS] " + label + " " + mutations + " header mutations handled");
    }

    private static final class RejectCase {
        final String name;
        final Map<String, String> headers;
        final byte[] body;
        final String rawQuery;
        final long now;

        RejectCase(String name, Map<String, String> headers, byte[] body, String rawQuery, long now) {
            this.name = name;
            this.headers = headers;
            this.body = body;
            this.rawQuery = rawQuery;
            this.now = now;
        }
    }


    private static RejectCase rejectCase(String name, String header, String value, String body, String rawQuery, long now) {
        Map<String, String> headers = vectorWebhookHeaders();
        if (header != null) {
            if (value == null || value.isEmpty()) {
                headers.remove(header);
            } else {
                headers.put(header, value);
            }
        }
        byte[] bytes = (body == null ? WEBHOOK_BODY : body).getBytes(StandardCharsets.UTF_8);
        return new RejectCase(name, headers, bytes, rawQuery, now);
    }

    static Map<String, String> vectorWebhookHeaders() {
        Map<String, String> headers = new LinkedHashMap<String, String>();
        headers.put("Content-Digest", WEBHOOK_DIGEST);
        headers.put("Content-Type", "application/json");
        headers.put("Signature", WEBHOOK_SIGNATURE);
        headers.put("Signature-Input", WEBHOOK_SIGNATURE_INPUT);
        headers.put("Webhook-Event-Id", WEBHOOK_EVENT_ID);
        return headers;
    }

    static byte[] sealedBoxOpen(byte[] sealed, byte[] recipientPublicKey, byte[] recipientPrivateKey) {
        byte[] ephemeralPublicKey = Arrays.copyOfRange(sealed, 0, 32);
        byte[] tag = Arrays.copyOfRange(sealed, 32, 48);
        byte[] ciphertext = Arrays.copyOfRange(sealed, 48, sealed.length);
        byte[] shared = new byte[32];
        new X25519PrivateKeyParameters(recipientPrivateKey, 0)
                .generateSecret(new X25519PublicKeyParameters(ephemeralPublicKey, 0), shared, 0);
        byte[] key = ProtocolAdapter.hsalsa20(shared, new byte[16]);
        XSalsa20Engine cipher = new XSalsa20Engine();
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), ProtocolAdapter.sealNonce(ephemeralPublicKey, recipientPublicKey)));
        byte[] macKey = new byte[32];
        cipher.processBytes(new byte[32], 0, 32, macKey, 0);
        Poly1305 mac = new Poly1305();
        mac.init(new KeyParameter(macKey));
        mac.update(ciphertext, 0, ciphertext.length);
        byte[] expected = new byte[16];
        mac.doFinal(expected, 0);
        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(tag, expected)) {
            throw new SecurityException("sealed box authentication failed");
        }
        byte[] plain = new byte[ciphertext.length];
        cipher.processBytes(ciphertext, 0, ciphertext.length, plain, 0);
        return plain;
    }

    private static ProtocolAdapter newAuth(String merchantKey) {
        return new ProtocolAdapter(ACCESS_KEY, merchantKey, BODY_KEY_ID, BODY_PUBLIC,
                Collections.singletonMap(WEBHOOK_KEY_ID, WEBHOOK_PUBLIC));
    }


    private static String pemFromSeed(String seedBase64) {
        byte[] prefix = {0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20};
        byte[] der = new byte[48];
        System.arraycopy(prefix, 0, der, 0, 16);
        System.arraycopy(b64(seedBase64), 0, der, 16, 32);
        return "-----BEGIN PRIVATE KEY-----\n" + Base64.getEncoder().encodeToString(der) + "\n-----END PRIVATE KEY-----\n";
    }

    static void expect(String name, String actual, String expected) {
        if (!expected.equals(actual)) {
            throw new AssertionError(name + " failed\n  expected: " + expected + "\n  actual: " + actual);
        }
        passed++;
        System.out.println("[PASS] " + name);
    }

    private static void expectRejected(String name, WebhookVerifierFn fn, String rawQuery,
                                       Map<String, String> headers, byte[] body, long now) {
        try {
            fn.verify("/webhook/payments", rawQuery, headers, body, now);
        } catch (SecurityException e) {
            passed++;
            System.out.println("[PASS] " + name + " (" + e.getMessage() + ")");
            return;
        } catch (Exception other) {
            throw new AssertionError(name + " unexpected exception: " + other);
        }
        throw new AssertionError(name + " was unexpectedly accepted");
    }

    static byte[] b64(String value) {
        return Base64.getDecoder().decode(value);
    }
}
