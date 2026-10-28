import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.StringJoiner;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * Merchant API wire protocol without the SDK, for Java 8 and later: Ed25519 request signing
 * (fixed RFC 9421 profile), sealed box POST body encryption, and platform webhook verification.
 *
 * <p>Crypto primitives come from BouncyCastle ({@code org.bouncycastle:bcprov-jdk18on}, pure Java, no
 * JNI/JNA, no native library) through its lightweight API only: no JCA provider is registered, so the
 * host application's global crypto configuration is untouched and the JCE key-size policy of old Java 8
 * builds does not apply. Base64, SHA-256, UUID and SecureRandom come from the JDK. This file itself
 * composes those primitives (sealed box, HSalsa20 key derivation); review it like any other code you ship.
 *
 * <p>Thread safety: an instance holds only immutable keys and may be shared by all request threads.
 */
public final class ProtocolAdapter {

    public static final String CONTENT_ENCRYPTION = "sealedbox-v1-x25519-xsalsa20poly1305";

    static final List<String> WRITE_COVERED = Collections.unmodifiableList(Arrays.asList(
            "@method", "@path", "content-type", "content-encryption", "content-digest", "idempotency-key", "merchant-access-key"));
    static final List<String> READ_COVERED = Collections.unmodifiableList(Arrays.asList(
            "@method", "@path", "@query", "merchant-access-key"));
    static final List<String> WEBHOOK_COVERED = Collections.unmodifiableList(Arrays.asList(
            "@method", "@path", "@query", "content-type", "content-digest", "webhook-event-id"));

    private static final long MAX_SIGNATURE_LIFETIME_SECONDS = 300;
    private static final int MAX_WIRE_BODY_BYTES = 2 << 20;
    private static final Pattern WEBHOOK_SIGNATURE = Pattern.compile("^platform=:([A-Za-z0-9+/]+={0,2}):$");
    private static final Pattern EVENT_ID = Pattern.compile("^evt_[0-9A-HJKMNP-TV-Z]{26}$");
    private static final Pattern UUID_V4 = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
    private static final Pattern KEY_ID = Pattern.compile("^[A-Za-z0-9_.:-]+$");
    // PKCS#8 prefix of an Ed25519 private key (RFC 8410); the 32-byte seed follows it.
    private static final byte[] PKCS8_ED25519_PREFIX = {
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20};
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String accessKey;
    private final Ed25519PrivateKeyParameters merchantPrivateKey;
    private final String platformBodyKeyId;
    private final byte[] platformBodyPublicKey;
    private final Map<String, Ed25519PublicKeyParameters> platformWebhookPublicKeys;

    /**
     * All values come from the merchant portal, except the private key, which the merchant generates.
     * Invalid configuration fails here, at startup, instead of on the first request.
     *
     * @param merchantPrivateKey Ed25519 private key: base64 of the 32-byte seed or the 64-byte seed||publicKey
     *                           form, or the PKCS#8 PEM written by {@code openssl genpkey -algorithm ed25519}
     * @param platformWebhookPublicKeys keyid to platform webhook Ed25519 public key (base64)
     */
    public ProtocolAdapter(String accessKey, String merchantPrivateKey, String platformBodyKeyId,
                           String platformBodyPublicKeyBase64, Map<String, String> platformWebhookPublicKeys) {
        if (accessKey == null || accessKey.trim().isEmpty() || !accessKey.trim().equals(accessKey)) {
            throw new IllegalArgumentException("accessKey is required");
        }
        if (platformBodyKeyId == null || !KEY_ID.matcher(platformBodyKeyId).matches()) {
            throw new IllegalArgumentException("platformBodyKeyId is invalid");
        }
        this.accessKey = accessKey;
        this.merchantPrivateKey = loadMerchantPrivateKey(merchantPrivateKey);
        this.platformBodyKeyId = platformBodyKeyId;
        this.platformBodyPublicKey = decodeKey32(platformBodyPublicKeyBase64, "platform X25519 public key");
        Map<String, Ed25519PublicKeyParameters> webhookKeys = new HashMap<String, Ed25519PublicKeyParameters>();
        if (platformWebhookPublicKeys != null) {
            for (Map.Entry<String, String> e : platformWebhookPublicKeys.entrySet()) {
                if (e.getKey() == null || !KEY_ID.matcher(e.getKey()).matches()) {
                    throw new IllegalArgumentException("platform webhook keyid is invalid: " + e.getKey());
                }
                webhookKeys.put(e.getKey(), new Ed25519PublicKeyParameters(
                        decodeKey32(e.getValue(), "platform webhook public key " + e.getKey()), 0));
            }
        }
        this.platformWebhookPublicKeys = Collections.unmodifiableMap(webhookKeys);
    }

    /** A request ready to send. Send body (null for GET) and every header exactly as returned. */
    public static final class SignedRequest {
        public final byte[] body;
        public final Map<String, String> headers;

        SignedRequest(byte[] body, Map<String, String> headers) {
            this.body = body;
            this.headers = Collections.unmodifiableMap(headers);
        }
    }

    /**
     * A webhook whose digest, freshness and platform signature have been verified. eventId is the signed
     * Webhook-Event-Id header. The platform signs the body too, so after parsing json with your own JSON
     * library, require its top-level "eventId" to equal this eventId before using the event.
     */
    public static final class VerifiedWebhook {
        public final String eventId;
        public final String json;

        VerifiedWebhook(String eventId, String json) {
            this.eventId = eventId;
            this.json = json;
        }
    }

    /** POST {path} carrying the plaintext business JSON (UTF-8 bytes) from the API Reference. */
    public SignedRequest signWrite(String path, byte[] businessJson) {
        return signSealedWrite(path, sealBody(businessJson), nowSeconds(), uuidV4(), uuidV4());
    }

    /** GET {path}?{rawQuery}. Send rawQuery byte for byte as passed here; never re-encode or reorder it. */
    public SignedRequest signRead(String path, String rawQuery) {
        return signRead(path, rawQuery, nowSeconds(), uuidV4());
    }

    /**
     * Verifies a platform webhook. path and rawQuery come from the URL the request arrived at (rawQuery
     * without '?', empty when absent); headers are the received headers; body must be the exact bytes
     * received, read before any JSON parsing. Every malformed, stale or unauthentic input throws
     * SecurityException, so callers need to map only that exception to a 401.
     *
     * <p>Then: compare the parsed top-level eventId with {@link VerifiedWebhook#eventId}, deduplicate on
     * eventId, match platform orderNo to the saved order under the expected merchant and validate business
     * fields before applying updates idempotently. Queue unknown orders and query with that merchant's
     * credentials first. Return 2xx only after the update is committed or durably queued.
     */
    public VerifiedWebhook verifyWebhook(String path, String rawQuery, Map<String, String> headers, byte[] body) {
        return verifyWebhook(path, rawQuery, headers, body, nowSeconds());
    }

    SignedRequest signSealedWrite(String path, byte[] envelope, long created, String nonce, String idempotencyKey) {
        Map<String, String> headers = new LinkedHashMap<String, String>();
        headers.put("Content-Type", "application/json");
        headers.put("Content-Encryption", CONTENT_ENCRYPTION);
        headers.put("Content-Digest", contentDigest(envelope));
        headers.put("Idempotency-Key", idempotencyKey);
        headers.put("Merchant-Access-Key", accessKey);
        Map<String, String> derived = new HashMap<String, String>();
        derived.put("@method", "POST");
        derived.put("@path", path);
        sign(headers, WRITE_COVERED, derived, created, nonce);
        return new SignedRequest(envelope, headers);
    }

    SignedRequest signRead(String path, String rawQuery, long created, String nonce) {
        Map<String, String> headers = new LinkedHashMap<String, String>();
        headers.put("Merchant-Access-Key", accessKey);
        Map<String, String> derived = new HashMap<String, String>();
        derived.put("@method", "GET");
        derived.put("@path", path);
        derived.put("@query", "?" + (rawQuery == null ? "" : rawQuery));
        sign(headers, READ_COVERED, derived, created, nonce);
        return new SignedRequest(null, headers);
    }

    VerifiedWebhook verifyWebhook(String path, String rawQuery, Map<String, String> headers, byte[] body, long now) {
        if (path == null || headers == null || body == null || body.length == 0 || body.length > MAX_WIRE_BODY_BYTES) {
            throw new SecurityException("bad webhook request");
        }
        Map<String, String> h = lowerCaseKeys(headers);
        if (!"application/json".equals(h.get("content-type"))) {
            throw new SecurityException("bad Content-Type");
        }
        String encoding = h.get("content-encoding");
        if (encoding != null && !"identity".equals(encoding)) {
            throw new SecurityException("bad Content-Encoding");
        }
        if (!contentDigest(body).equals(h.get("content-digest"))) {
            throw new SecurityException("content digest mismatch");
        }
        String eventId = h.get("webhook-event-id");
        if (eventId == null || !EVENT_ID.matcher(eventId).matches()) {
            throw new SecurityException("bad Webhook-Event-Id");
        }

        String signatureInput = h.get("signature-input");
        Map<String, String> params = parsePlatformSignatureInput(signatureInput);
        long created = parseUnixSeconds(params.get("created"));
        long expires = parseUnixSeconds(params.get("expires"));
        if (expires <= created || expires - created > MAX_SIGNATURE_LIFETIME_SECONDS
                || now > expires || now < created - MAX_SIGNATURE_LIFETIME_SECONDS) {
            throw new SecurityException("signature expired");
        }
        if (!"ed25519".equals(params.get("alg")) || !UUID_V4.matcher(params.get("nonce")).matches()) {
            throw new SecurityException("bad Signature-Input");
        }
        Ed25519PublicKeyParameters key = platformWebhookPublicKeys.get(params.get("keyid"));
        if (key == null) {
            throw new SecurityException("unknown keyid");
        }

        Map<String, String> derived = new HashMap<String, String>();
        derived.put("@method", "POST");
        derived.put("@path", path);
        derived.put("@query", "?" + (rawQuery == null ? "" : rawQuery));
        byte[] base = signatureBase(WEBHOOK_COVERED, derived, h, signatureInput.substring("platform=".length()));

        byte[] signature = decodeSignature(h.get("signature"));
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, key);
        verifier.update(base, 0, base.length);
        if (!verifier.verifySignature(signature)) {
            throw new SecurityException("signature invalid");
        }
        return new VerifiedWebhook(eventId, new String(body, StandardCharsets.UTF_8));
    }

    // ---- RFC 9421 profile -------------------------------------------------------------------

    private void sign(Map<String, String> headers, List<String> covered, Map<String, String> derived,
                      long created, String nonce) {
        String params = "(" + quotedList(covered) + ");created=" + created
                + ";expires=" + (created + MAX_SIGNATURE_LIFETIME_SECONDS)
                + ";nonce=\"" + nonce + "\";alg=\"ed25519\"";
        byte[] base = signatureBase(covered, derived, headers, params);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, merchantPrivateKey);
        signer.update(base, 0, base.length);
        headers.put("Signature-Input", "merchant=" + params);
        headers.put("Signature", "merchant=:" + Base64.getEncoder().encodeToString(signer.generateSignature()) + ":");
    }

    /**
     * One line per covered component in order, then the "@signature-params" line, joined by "\n" with no
     * trailing newline. Derived components come from derived, header components from headers.
     */
    static byte[] signatureBase(List<String> covered, Map<String, String> derived, Map<String, String> headers,
                                String signatureParams) {
        Map<String, String> lower = lowerCaseKeys(headers);
        StringJoiner lines = new StringJoiner("\n");
        for (String component : covered) {
            String value = derived.containsKey(component) ? derived.get(component) : lower.get(component);
            if (value == null || value.isEmpty() || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
                throw new SecurityException("missing or invalid covered component " + component);
            }
            lines.add("\"" + component + "\": " + value);
        }
        lines.add("\"@signature-params\": " + signatureParams);
        return lines.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Mirrors the platform parser: exactly the six webhook components in order, then created, expires,
     * nonce, keyid and alg in any order, each once. Returns the raw parameter values.
     */
    private static Map<String, String> parsePlatformSignatureInput(String value) {
        String prefix = "platform=(";
        if (value == null || !value.startsWith(prefix)) {
            throw new SecurityException("bad Signature-Input");
        }
        int closing = value.indexOf(')');
        if (closing < 0 || closing + 1 >= value.length() || value.charAt(closing + 1) != ';'
                || !value.substring(prefix.length(), closing).equals(quotedList(WEBHOOK_COVERED))) {
            throw new SecurityException("bad Signature-Input");
        }
        Map<String, String> params = new HashMap<String, String>();
        for (String part : value.substring(closing + 2).split(";", -1)) {
            int eq = part.indexOf('=');
            String name = eq <= 0 ? "" : part.substring(0, eq);
            String raw = eq <= 0 ? "" : part.substring(eq + 1);
            boolean numeric = name.equals("created") || name.equals("expires");
            boolean quoted = name.equals("nonce") || name.equals("keyid") || name.equals("alg");
            if ((!numeric && !quoted) || params.containsKey(name)) {
                throw new SecurityException("bad Signature-Input");
            }
            if (quoted) {
                if (raw.length() < 2 || raw.charAt(0) != '"' || raw.charAt(raw.length() - 1) != '"'
                        || raw.substring(1, raw.length() - 1).indexOf('"') >= 0
                        || raw.substring(1, raw.length() - 1).indexOf('\\') >= 0) {
                    throw new SecurityException("bad Signature-Input");
                }
                raw = raw.substring(1, raw.length() - 1);
            }
            params.put(name, raw);
        }
        if (params.size() != 5) {
            throw new SecurityException("bad Signature-Input");
        }
        return params;
    }

    private static long parseUnixSeconds(String raw) {
        if (raw == null || raw.isEmpty() || raw.length() > 12) {
            throw new SecurityException("bad Signature-Input");
        }
        for (int i = 0; i < raw.length(); i++) {
            if (raw.charAt(i) < '0' || raw.charAt(i) > '9') {
                throw new SecurityException("bad Signature-Input");
            }
        }
        long value = Long.parseLong(raw);
        if (value <= 0) {
            throw new SecurityException("bad Signature-Input");
        }
        return value;
    }

    private static byte[] decodeSignature(String header) {
        Matcher m = WEBHOOK_SIGNATURE.matcher(header == null ? "" : header);
        if (!m.matches()) {
            throw new SecurityException("bad Signature");
        }
        byte[] signature;
        try {
            signature = Base64.getDecoder().decode(m.group(1));
        } catch (IllegalArgumentException e) {
            throw new SecurityException("bad Signature");
        }
        if (signature.length != 64) {
            throw new SecurityException("bad Signature");
        }
        return signature;
    }

    /** RFC 9530 Content-Digest over the exact wire bytes. */
    static String contentDigest(byte[] body) {
        try {
            byte[] sum = MessageDigest.getInstance("SHA-256").digest(body);
            return "sha-256=:" + Base64.getEncoder().encodeToString(sum) + ":";
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("every Java runtime provides SHA-256", e);
        }
    }

    // ---- sealed box body envelope ----------------------------------------------------------

    byte[] sealBody(byte[] businessJson) {
        if (businessJson == null || businessJson.length == 0 || businessJson.length > (1 << 20)) {
            throw new IllegalArgumentException("business JSON must be 1 byte to 1 MiB");
        }
        String ciphertext = Base64.getEncoder().encodeToString(sealedBox(businessJson, platformBodyPublicKey));
        // keyId is restricted to [A-Za-z0-9_.:-] and base64 needs no escaping, so plain concatenation is valid JSON
        String envelope = "{\"version\":1,\"alg\":\"" + CONTENT_ENCRYPTION + "\",\"keyId\":\"" + platformBodyKeyId
                + "\",\"ciphertext\":\"" + ciphertext + "\"}";
        return envelope.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * libsodium crypto_box_seal, byte compatible:
     * ephemeral_pk(32) || Poly1305 tag(16) || XSalsa20 ciphertext, with
     * nonce = BLAKE2b-192(ephemeral_pk || recipient_pk) and key = HSalsa20(X25519(ephemeral_sk, recipient_pk), 0^16).
     */
    static byte[] sealedBox(byte[] message, byte[] recipientPublicKey) {
        X25519PrivateKeyParameters ephemeral = new X25519PrivateKeyParameters(RANDOM);
        byte[] ephemeralPublicKey = ephemeral.generatePublicKey().getEncoded();
        byte[] shared = new byte[32];
        ephemeral.generateSecret(new X25519PublicKeyParameters(recipientPublicKey, 0), shared, 0);
        byte[] key = hsalsa20(shared, new byte[16]);
        byte[] boxed = secretBox(message, sealNonce(ephemeralPublicKey, recipientPublicKey), key);
        Arrays.fill(shared, (byte) 0);
        Arrays.fill(key, (byte) 0);
        byte[] sealed = new byte[32 + boxed.length];
        System.arraycopy(ephemeralPublicKey, 0, sealed, 0, 32);
        System.arraycopy(boxed, 0, sealed, 32, boxed.length);
        return sealed;
    }

    static byte[] sealNonce(byte[] ephemeralPublicKey, byte[] recipientPublicKey) {
        Blake2bDigest digest = new Blake2bDigest(192);
        digest.update(ephemeralPublicKey, 0, ephemeralPublicKey.length);
        digest.update(recipientPublicKey, 0, recipientPublicKey.length);
        byte[] nonce = new byte[24];
        digest.doFinal(nonce, 0);
        return nonce;
    }

    /** crypto_secretbox_xsalsa20poly1305: keystream bytes 0..31 key Poly1305, the message is XORed from byte 32. */
    static byte[] secretBox(byte[] message, byte[] nonce, byte[] key) {
        XSalsa20Engine cipher = new XSalsa20Engine();
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        byte[] macKey = new byte[32];
        cipher.processBytes(new byte[32], 0, 32, macKey, 0);
        byte[] out = new byte[16 + message.length];
        cipher.processBytes(message, 0, message.length, out, 16);
        Poly1305 mac = new Poly1305();
        mac.init(new KeyParameter(macKey));
        mac.update(out, 16, message.length);
        mac.doFinal(out, 0);
        Arrays.fill(macKey, (byte) 0);
        return out;
    }

    /**
     * HSalsa20, which crypto_box_beforenm applies to the X25519 shared secret. BouncyCastle exposes the Salsa20
     * core but not HSalsa20; salsaCore adds the input words back after the 20 rounds, so they are subtracted
     * here exactly as BouncyCastle's own XSalsa20Engine does when it derives its subkey.
     */
    static byte[] hsalsa20(byte[] key, byte[] input) {
        int[] state = new int[16];
        state[0] = 0x61707865;   // "expand 32-byte k"
        state[5] = 0x3320646e;
        state[10] = 0x79622d32;
        state[15] = 0x6b206574;
        for (int i = 0; i < 4; i++) {
            state[1 + i] = le32(key, 4 * i);
            state[11 + i] = le32(key, 16 + 4 * i);
            state[6 + i] = le32(input, 4 * i);
        }
        int[] mixed = new int[16];
        Salsa20Engine.salsaCore(20, state, mixed);
        int[] outputWords = {0, 5, 10, 15, 6, 7, 8, 9};
        byte[] out = new byte[32];
        for (int i = 0; i < outputWords.length; i++) {
            int w = mixed[outputWords[i]] - state[outputWords[i]];
            out[4 * i] = (byte) w;
            out[4 * i + 1] = (byte) (w >>> 8);
            out[4 * i + 2] = (byte) (w >>> 16);
            out[4 * i + 3] = (byte) (w >>> 24);
        }
        Arrays.fill(state, 0);
        Arrays.fill(mixed, 0);
        return out;
    }

    // ---- keys and helpers ------------------------------------------------------------------

    static Ed25519PrivateKeyParameters loadMerchantPrivateKey(String value) {
        if (value == null) {
            throw new IllegalArgumentException("merchant private key is required");
        }
        String trimmed = value.trim();
        if (trimmed.startsWith("-----BEGIN PRIVATE KEY-----")) {
            String b64 = trimmed.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(b64);
            if (der.length != 48 || !Arrays.equals(Arrays.copyOf(der, 16), PKCS8_ED25519_PREFIX)) {
                throw new IllegalArgumentException("PEM is not an Ed25519 PKCS#8 private key");
            }
            return new Ed25519PrivateKeyParameters(der, 16);
        }
        byte[] raw = Base64.getDecoder().decode(trimmed);
        if (raw.length == 32) {
            return new Ed25519PrivateKeyParameters(raw, 0);
        }
        if (raw.length == 64) {
            Ed25519PrivateKeyParameters key = new Ed25519PrivateKeyParameters(raw, 0);
            if (!Arrays.equals(key.generatePublicKey().getEncoded(), Arrays.copyOfRange(raw, 32, 64))) {
                throw new IllegalArgumentException("64-byte key: public half does not match the seed");
            }
            return key;
        }
        throw new IllegalArgumentException("merchant private key must be a 32-byte seed, a 64-byte key or a PKCS#8 PEM");
    }

    private static byte[] decodeKey32(String base64, String name) {
        byte[] raw = base64 == null ? new byte[0] : Base64.getDecoder().decode(base64.trim());
        if (raw.length != 32) {
            throw new IllegalArgumentException(name + " must be 32 bytes");
        }
        return raw;
    }

    private static String quotedList(List<String> covered) {
        StringJoiner joined = new StringJoiner(" ");
        for (String component : covered) {
            joined.add("\"" + component + "\"");
        }
        return joined.toString();
    }

    /** Header names are case-insensitive; two entries that differ only in case are ambiguous and rejected. */
    private static Map<String, String> lowerCaseKeys(Map<String, String> headers) {
        Map<String, String> lower = new HashMap<String, String>();
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey() == null) {
                continue;
            }
            String name = e.getKey().toLowerCase(Locale.ROOT);
            if (lower.containsKey(name)) {
                throw new SecurityException("duplicate header " + name);
            }
            lower.put(name, e.getValue() == null ? null : e.getValue().trim());
        }
        return lower;
    }

    private static int le32(byte[] b, int off) {
        return (b[off] & 0xff) | (b[off + 1] & 0xff) << 8 | (b[off + 2] & 0xff) << 16 | (b[off + 3] & 0xff) << 24;
    }

    /** Lowercase random UUID v4, the form the gateway accepts for nonce and Idempotency-Key. */
    static String uuidV4() {
        return UUID.randomUUID().toString();
    }

    private static long nowSeconds() {
        return System.currentTimeMillis() / 1000;
    }
}
