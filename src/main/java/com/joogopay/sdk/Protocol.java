package com.joogopay.sdk;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * Protocol core: merchant request signing and platform webhook verification.
 *
 * <p>The protocol documents for signing, body encryption and webhooks are the source of truth;
 * the shared vectors under protocol/testdata keep every SDK consistent with them.
 */
public final class Protocol {

    public static final String HEADER_MERCHANT_ACCESS_KEY = "Merchant-Access-Key";
    public static final String HEADER_WEBHOOK_EVENT_ID = "Webhook-Event-Id";
    public static final String HEADER_CONTENT_ENCRYPTION = "Content-Encryption";
    public static final String HEADER_CONTENT_DIGEST = "Content-Digest";
    public static final String HEADER_IDEMPOTENCY_KEY = "Idempotency-Key";
    public static final String HEADER_SIGNATURE_INPUT = "Signature-Input";
    public static final String HEADER_SIGNATURE = "Signature";

    public static final String SIGNATURE_LABEL_MERCHANT = "merchant";
    public static final String SIGNATURE_LABEL_PLATFORM = "platform";
    public static final String SIGNATURE_ALG_ED25519 = "ed25519";
    public static final String CONTENT_ENCRYPTION = "sealedbox-v1-x25519-xsalsa20poly1305";

    public static final int MAX_PLAIN_BODY_BYTES = 1 << 20;
    public static final int MAX_WIRE_BODY_BYTES = 2 << 20;
    /** Signature lifetime in seconds. */
    public static final long MAX_SIGNATURE_LIFETIME = 300L;
    public static final int X25519_PUBLIC_KEY_SIZE = 32;
    public static final int X25519_PRIVATE_KEY_SIZE = 32;
    public static final int ED25519_PUBLIC_KEY_SIZE = 32;
    public static final int ED25519_SIGNATURE_SIZE = 64;

    /** Covered components in signature-base order; the lists are fixed by the protocol. */
    public static final List<String> MERCHANT_WRITE_COVERED = List.of(
            "@method", "@path", "content-type", "content-encryption",
            "content-digest", "idempotency-key", "merchant-access-key");
    public static final List<String> MERCHANT_READ_COVERED = List.of(
            "@method", "@path", "@query", "merchant-access-key");
    public static final List<String> PLATFORM_COVERED = List.of(
            "@method", "@path", "@query", "content-type", "content-digest", "webhook-event-id");

    /** Public lookup fields a signed GET query may carry. */
    public static final Set<String> ALLOWED_READ_QUERY_FIELDS = Set.of(
            "orderNo", "merchantOrderNo", "currency", "payMethod", "status",
            "startTime", "endTime", "page", "pageSize", "consentNo",
            "subscriptionPaymentNo", "planNo", "merchantPlanNo", "merchantCustomerNo",
            "subscriptionNo", "merchantSubscriptionNo", "invoiceNo");

    private static final String CROCKFORD32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Map<String, String> COMPONENT_HEADERS = Map.of(
            "content-type", "Content-Type",
            "content-encryption", HEADER_CONTENT_ENCRYPTION,
            "content-digest", HEADER_CONTENT_DIGEST,
            "idempotency-key", HEADER_IDEMPOTENCY_KEY,
            "merchant-access-key", HEADER_MERCHANT_ACCESS_KEY,
            "webhook-event-id", HEADER_WEBHOOK_EVENT_ID);

    private Protocol() {
    }

    /** RFC 9421 signature parameters of the fixed profile; keyId is set only for platform webhooks. */
    public record SignatureParams(
            String label,
            List<String> covered,
            long created,
            long expires,
            String nonce,
            String keyId,
            String alg) {
    }

    /** Encrypted wire body of a merchant POST. */
    public record BodyEnvelope(int version, String alg, String keyId, String ciphertext) {
    }

    private static SignatureParams makeParams(
            String label, List<String> covered, String nonce, long now, String keyId) {
        return new SignatureParams(
                label, covered, now, now + MAX_SIGNATURE_LIFETIME, nonce, keyId,
                SIGNATURE_ALG_ED25519);
    }

    public static SignatureParams newMerchantWriteSignatureParams(String nonce, long now) {
        return makeParams(SIGNATURE_LABEL_MERCHANT, MERCHANT_WRITE_COVERED, nonce, now, "");
    }

    public static SignatureParams newMerchantReadSignatureParams(String nonce, long now) {
        return makeParams(SIGNATURE_LABEL_MERCHANT, MERCHANT_READ_COVERED, nonce, now, "");
    }

    public static SignatureParams newPlatformSignatureParams(String keyId, String nonce, long now) {
        return makeParams(SIGNATURE_LABEL_PLATFORM, PLATFORM_COVERED, nonce, now, keyId);
    }

    /** Lowercase UUID v4. */
    public static String newNonce() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        bytes[6] = (byte) ((bytes[6] & 0x0f) | 0x40);
        bytes[8] = (byte) ((bytes[8] & 0x3f) | 0x80);
        long high = 0;
        long low = 0;
        for (int i = 0; i < 8; i++) {
            high = (high << 8) | (bytes[i] & 0xffL);
        }
        for (int i = 8; i < 16; i++) {
            low = (low << 8) | (bytes[i] & 0xffL);
        }
        return new UUID(high, low).toString();
    }

    /** No escaping: protocol values are ASCII and never contain quotes or backslashes. */
    private static String quote(String value) {
        return '"' + value + '"';
    }

    public static String signatureInputValue(SignatureParams params) {
        var components = new StringBuilder();
        for (int i = 0; i < params.covered().size(); i++) {
            if (i > 0) {
                components.append(' ');
            }
            components.append(quote(params.covered().get(i)));
        }
        var value = new StringBuilder()
                .append('(').append(components).append(')')
                .append(";created=").append(params.created())
                .append(";expires=").append(params.expires())
                .append(";nonce=").append(quote(params.nonce()));
        if (SIGNATURE_LABEL_PLATFORM.equals(params.label())) {
            value.append(";keyid=").append(quote(params.keyId()));
        }
        return value.append(";alg=").append(quote(params.alg())).toString();
    }

    public static String signatureInputHeader(SignatureParams params) {
        validateSignatureParams(params, params.created());
        return params.label() + "=" + signatureInputValue(params);
    }

    private static String componentValue(
            String component, String method, String path, String rawQuery,
            Map<String, String> headers) {
        switch (component) {
            case "@method":
                return method;
            case "@path":
                return path == null || path.isEmpty() ? "/" : path;
            case "@query":
                return "?" + (rawQuery == null ? "" : rawQuery);
            default:
                break;
        }
        String name = COMPONENT_HEADERS.get(component);
        if (name == null) {
            throw new JoogopayException.InvalidHeader("unknown covered component: " + component);
        }
        var lowered = new HashMap<String, String>();
        if (headers != null) {
            headers.forEach((k, v) -> lowered.put(k.toLowerCase(Locale.ROOT), v));
        }
        String value = lowered.get(name.toLowerCase(Locale.ROOT));
        value = value == null ? "" : value.trim();
        if (!validHeaderValue(value)) {
            throw new JoogopayException.InvalidHeader("missing or invalid header: " + name);
        }
        return value;
    }

    /** Builds the RFC 9421 signature base. */
    public static byte[] signatureBase(
            SignatureParams params, String method, String path, String rawQuery,
            Map<String, String> headers) {
        if (params.covered() == null || params.covered().isEmpty()) {
            throw new JoogopayException.InvalidHeader("empty covered components");
        }
        var lines = new ArrayList<String>(params.covered().size() + 1);
        for (String component : params.covered()) {
            lines.add(quote(component) + ": "
                    + componentValue(component, method, path, rawQuery, headers));
        }
        lines.add(quote("@signature-params") + ": " + signatureInputValue(params));
        return String.join("\n", lines).getBytes(StandardCharsets.UTF_8);
    }

    private static boolean validHeaderValue(String value) {
        return value != null && !value.isEmpty() && value.trim().equals(value)
                && value.indexOf('\r') < 0 && value.indexOf('\n') < 0;
    }

    /** Lowercase UUID v4 only; uppercase hex is rejected. */
    public static boolean validUuidV4(String value) {
        if (value == null || value.length() != 36) {
            return false;
        }
        for (int i = 0; i < 36; i++) {
            char ch = value.charAt(i);
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                if (ch != '-') {
                    return false;
                }
            } else if (i == 14) {
                if (ch != '4') {
                    return false;
                }
            } else if (i == 19) {
                if ("89ab".indexOf(ch) < 0) {
                    return false;
                }
            } else if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f')) {
                return false;
            }
        }
        return true;
    }

    public static void validateIdempotencyKey(String value) {
        if (!validUuidV4(value)) {
            throw new JoogopayException.InvalidHeader(
                    "Idempotency-Key must be a lowercase UUID v4");
        }
    }

    public static void validateWebhookEventId(String value) {
        if (value == null || !value.startsWith("evt_") || value.length() != 30) {
            throw new JoogopayException.InvalidHeader("invalid Webhook-Event-Id");
        }
        for (int i = 4; i < value.length(); i++) {
            if (CROCKFORD32.indexOf(value.charAt(i)) < 0) {
                throw new JoogopayException.InvalidHeader("invalid Webhook-Event-Id");
            }
        }
    }

    /** A read query may carry only public lookup fields, each at most once and non-blank. */
    public static void validateMerchantReadQuery(String rawQuery) {
        if (rawQuery == null || rawQuery.isEmpty()) {
            return;
        }
        var seen = new HashMap<String, Boolean>();
        for (String pair : rawQuery.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int idx = pair.indexOf('=');
            String key = idx < 0 ? pair : pair.substring(0, idx);
            String value = idx < 0 ? "" : pair.substring(idx + 1);
            key = java.net.URLDecoder.decode(key, StandardCharsets.UTF_8);
            value = java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
            if (!ALLOWED_READ_QUERY_FIELDS.contains(key)
                    || seen.containsKey(key)
                    || value.trim().isEmpty()) {
                throw new JoogopayException.InvalidHeader("query field not allowed: " + key);
            }
            seen.put(key, true);
        }
    }

    public static void validateFreshness(SignatureParams params, long now) {
        if (params.created() <= 0 || params.expires() <= 0
                || params.expires() <= params.created()
                || params.expires() - params.created() > MAX_SIGNATURE_LIFETIME) {
            throw new JoogopayException.ExpiredSignature("invalid signature lifetime");
        }
        if (now < params.created() - MAX_SIGNATURE_LIFETIME || now > params.expires()) {
            throw new JoogopayException.ExpiredSignature("signature expired");
        }
    }

    private static boolean coveredComponentsAllowed(String label, List<String> covered) {
        if (SIGNATURE_LABEL_MERCHANT.equals(label)) {
            return MERCHANT_WRITE_COVERED.equals(covered) || MERCHANT_READ_COVERED.equals(covered);
        }
        if (SIGNATURE_LABEL_PLATFORM.equals(label)) {
            return PLATFORM_COVERED.equals(covered);
        }
        return false;
    }

    public static void validateSignatureParams(SignatureParams params, long now) {
        if (params.label() == null || params.label().isEmpty()
                || !SIGNATURE_ALG_ED25519.equals(params.alg())
                || !validUuidV4(params.nonce())) {
            throw new JoogopayException.InvalidHeader("invalid signature params");
        }
        if (SIGNATURE_LABEL_PLATFORM.equals(params.label())) {
            if (!validHeaderValue(params.keyId())) {
                throw new JoogopayException.InvalidHeader("platform signature requires keyid");
            }
        } else if (!SIGNATURE_LABEL_MERCHANT.equals(params.label())) {
            throw new JoogopayException.InvalidHeader("unknown signature label");
        }
        if (!coveredComponentsAllowed(params.label(), params.covered())) {
            throw new JoogopayException.InvalidHeader("covered components not allowed");
        }
        validateFreshness(params, now);
    }

    public static SignatureParams parseSignatureInput(
            String value, String label, List<String> covered) {
        String prefix = label + "=(";
        if (value == null || !value.startsWith(prefix)) {
            throw new JoogopayException.InvalidHeader("bad Signature-Input label");
        }
        int closing = value.indexOf(')');
        if (closing < 0 || closing + 1 >= value.length() || value.charAt(closing + 1) != ';') {
            throw new JoogopayException.InvalidHeader("bad Signature-Input components");
        }
        String[] rawComponents = value.substring(prefix.length(), closing).trim().split("\\s+");
        if (rawComponents.length != covered.size()) {
            throw new JoogopayException.InvalidHeader("covered components mismatch");
        }
        for (int i = 0; i < rawComponents.length; i++) {
            String unquoted = unquote(rawComponents[i]);
            if (!unquoted.equals(covered.get(i))) {
                throw new JoogopayException.InvalidHeader("covered components mismatch");
            }
        }

        String[] parts = value.substring(closing + 2).split(";");
        int expected = SIGNATURE_LABEL_PLATFORM.equals(label) ? 5 : 4;
        if (parts.length != expected) {
            throw new JoogopayException.InvalidHeader("bad Signature-Input params");
        }
        var got = new LinkedHashMap<String, String>();
        for (String part : parts) {
            int idx = part.indexOf('=');
            if (idx <= 0) {
                throw new JoogopayException.InvalidHeader("bad Signature-Input params");
            }
            String key = part.substring(0, idx);
            if (got.containsKey(key)) {
                throw new JoogopayException.InvalidHeader("bad Signature-Input params");
            }
            got.put(key, part.substring(idx + 1));
        }
        for (String key : got.keySet()) {
            if (!Set.of("created", "expires", "nonce", "keyid", "alg").contains(key)) {
                throw new JoogopayException.InvalidHeader("unknown Signature-Input param: " + key);
            }
        }
        if (got.containsKey("keyid") && !SIGNATURE_LABEL_PLATFORM.equals(label)) {
            throw new JoogopayException.InvalidHeader(
                    "merchant signature must not carry keyid");
        }
        try {
            return new SignatureParams(
                    label,
                    covered,
                    Long.parseLong(got.get("created")),
                    Long.parseLong(got.get("expires")),
                    unquote(got.get("nonce")),
                    got.containsKey("keyid") ? unquote(got.get("keyid")) : "",
                    unquote(got.get("alg")));
        } catch (NumberFormatException | NullPointerException e) {
            throw new JoogopayException.InvalidHeader("bad Signature-Input params");
        }
    }

    private static String unquote(String raw) {
        if (raw == null || raw.length() < 2 || raw.charAt(0) != '"'
                || raw.charAt(raw.length() - 1) != '"') {
            throw new JoogopayException.InvalidHeader("bad quoted value: " + raw);
        }
        return raw.substring(1, raw.length() - 1);
    }

    public static SignatureParams parseMerchantWriteSignatureInput(String value) {
        return parseSignatureInput(value, SIGNATURE_LABEL_MERCHANT, MERCHANT_WRITE_COVERED);
    }

    public static SignatureParams parseMerchantReadSignatureInput(String value) {
        return parseSignatureInput(value, SIGNATURE_LABEL_MERCHANT, MERCHANT_READ_COVERED);
    }

    public static SignatureParams parsePlatformSignatureInput(String value) {
        return parseSignatureInput(value, SIGNATURE_LABEL_PLATFORM, PLATFORM_COVERED);
    }

    /** RFC 9530 Content-Digest value using sha-256. */
    public static String contentDigestSha256(byte[] body) {
        try {
            byte[] sum = MessageDigest.getInstance("SHA-256").digest(body);
            return "sha-256=:" + Base64.getEncoder().encodeToString(sum) + ":";
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static boolean verifyContentDigest(byte[] body, String header) {
        if (header == null) {
            return false;
        }
        return MessageDigest.isEqual(
                contentDigestSha256(body).getBytes(StandardCharsets.UTF_8),
                header.getBytes(StandardCharsets.UTF_8));
    }

    /** Accepts a 32-byte seed or the 64-byte seed||pub form; only the seed is used. */
    private static Ed25519PrivateKeyParameters privateKey(byte[] raw) {
        if (raw == null || (raw.length != 32 && raw.length != 64)) {
            throw new JoogopayException.InvalidSignature(
                    "ed25519 private key must be 32 or 64 bytes");
        }
        return new Ed25519PrivateKeyParameters(raw, 0);
    }

    public static String signEd25519(byte[] privateKeyBytes, String label, byte[] base) {
        if (label == null || label.isEmpty() || base == null || base.length == 0) {
            throw new JoogopayException.InvalidSignature("empty label or signature base");
        }
        var signer = new Ed25519Signer();
        signer.init(true, privateKey(privateKeyBytes));
        signer.update(base, 0, base.length);
        return signatureHeader(label, signer.generateSignature());
    }

    public static void verifyEd25519(byte[] publicKey, byte[] base, byte[] signature) {
        if (publicKey == null || publicKey.length != ED25519_PUBLIC_KEY_SIZE
                || base == null || base.length == 0
                || signature == null || signature.length != ED25519_SIGNATURE_SIZE) {
            throw new JoogopayException.InvalidSignature("invalid ed25519 verify input");
        }
        var verifier = new Ed25519Signer();
        try {
            verifier.init(false, new Ed25519PublicKeyParameters(publicKey, 0));
        } catch (IllegalArgumentException e) {
            // BouncyCastle rejects an invalid curve point (e.g. all zeros) with a raw
            // IllegalArgumentException while building the key; libsodium-based SDKs only fail
            // at verification, so it is folded into the same exception type here.
            throw new JoogopayException.InvalidSignature("invalid ed25519 public key");
        }
        verifier.update(base, 0, base.length);
        if (!verifier.verifySignature(signature)) {
            throw new JoogopayException.InvalidSignature("signature verification failed");
        }
    }

    public static String signatureHeader(String label, byte[] signature) {
        if (!validHeaderValue(label) || signature == null
                || signature.length != ED25519_SIGNATURE_SIZE) {
            throw new JoogopayException.InvalidSignature("invalid signature header input");
        }
        return label + "=:" + Base64.getEncoder().encodeToString(signature) + ":";
    }

    public static byte[] parseSignature(String value, String label) {
        if (!validHeaderValue(label)) {
            throw new JoogopayException.InvalidSignature("invalid signature label");
        }
        String prefix = label + "=:";
        if (value == null || !value.startsWith(prefix) || !value.endsWith(":")) {
            throw new JoogopayException.InvalidSignature("malformed Signature header");
        }
        byte[] signature;
        try {
            signature = Base64.getDecoder()
                    .decode(value.substring(prefix.length(), value.length() - 1));
        } catch (IllegalArgumentException e) {
            throw new JoogopayException.InvalidSignature("malformed Signature header");
        }
        if (signature.length != ED25519_SIGNATURE_SIZE) {
            throw new JoogopayException.InvalidSignature("malformed Signature header");
        }
        return signature;
    }

    /** Encrypts a plaintext POST body for the platform's X25519 key and returns the wire body. */
    public static byte[] sealBodyEnvelope(byte[] plaintext, byte[] publicKey, String keyId) {
        if (plaintext == null || plaintext.length == 0 || plaintext.length > MAX_PLAIN_BODY_BYTES) {
            throw new JoogopayException.InvalidEnvelope("invalid plaintext size");
        }
        if (publicKey == null || publicKey.length != X25519_PUBLIC_KEY_SIZE
                || !validHeaderValue(keyId)) {
            throw new JoogopayException.InvalidEnvelope("invalid platform body key");
        }
        byte[] ciphertext = SealedBox.seal(plaintext, publicKey);
        // hand-built so the field order stays the same across SDKs
        String json = "{\"version\":1,\"alg\":\"" + CONTENT_ENCRYPTION + "\",\"keyId\":\""
                + keyId + "\",\"ciphertext\":\""
                + Base64.getEncoder().encodeToString(ciphertext) + "\"}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    /** Parses and validates the envelope without decrypting it. */
    public static BodyEnvelope decodeBodyEnvelope(byte[] wireBody) {
        if (wireBody == null || wireBody.length == 0 || wireBody.length > MAX_WIRE_BODY_BYTES) {
            throw new JoogopayException.InvalidEnvelope("invalid envelope size");
        }
        Map<String, Object> raw;
        try {
            raw = Json.readObject(wireBody);
        } catch (RuntimeException e) {
            throw new JoogopayException.InvalidEnvelope("envelope is not valid json");
        }
        if (!raw.keySet().equals(Set.of("version", "alg", "keyId", "ciphertext"))) {
            throw new JoogopayException.InvalidEnvelope("unexpected envelope fields");
        }
        Object version = raw.get("version");
        Object alg = raw.get("alg");
        Object keyId = raw.get("keyId");
        Object ciphertext = raw.get("ciphertext");
        if (!(version instanceof Number number) || number.intValue() != 1
                || !CONTENT_ENCRYPTION.equals(alg)
                || !(keyId instanceof String keyIdValue) || !validHeaderValue(keyIdValue)
                || !(ciphertext instanceof String ciphertextValue) || ciphertextValue.isEmpty()) {
            throw new JoogopayException.InvalidEnvelope("invalid envelope");
        }
        try {
            Base64.getDecoder().decode(ciphertextValue);
        } catch (IllegalArgumentException e) {
            throw new JoogopayException.InvalidEnvelope("invalid envelope ciphertext");
        }
        return new BodyEnvelope(1, (String) alg, keyIdValue, ciphertextValue);
    }

    public static String peekBodyEnvelopeKeyId(byte[] wireBody) {
        try {
            return decodeBodyEnvelope(wireBody).keyId();
        } catch (JoogopayException.InvalidEnvelope e) {
            return "";
        }
    }

    /** Decrypts the envelope with the platform's X25519 key pair; returns the plaintext and keyId. */
    public static Map.Entry<byte[], String> openBodyEnvelope(
            byte[] wireBody, byte[] publicKey, byte[] privateKey) {
        if (publicKey == null || publicKey.length != X25519_PUBLIC_KEY_SIZE
                || privateKey == null || privateKey.length != X25519_PRIVATE_KEY_SIZE) {
            throw new JoogopayException.InvalidEnvelope("invalid platform body key pair");
        }
        BodyEnvelope envelope = decodeBodyEnvelope(wireBody);
        byte[] plaintext;
        try {
            plaintext = SealedBox.sealOpen(
                    Base64.getDecoder().decode(envelope.ciphertext()), publicKey, privateKey);
        } catch (RuntimeException e) {
            throw new JoogopayException.InvalidEnvelope("envelope decrypt failed");
        }
        if (plaintext.length == 0 || plaintext.length > MAX_PLAIN_BODY_BYTES) {
            throw new JoogopayException.InvalidEnvelope("invalid plaintext size");
        }
        return Map.entry(plaintext, envelope.keyId());
    }

    static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    static byte[] copy(byte[] value) {
        return Arrays.copyOf(value, value.length);
    }
}
