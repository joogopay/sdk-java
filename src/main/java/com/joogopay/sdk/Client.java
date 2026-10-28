package com.joogopay.sdk;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.util.Timeout;

/**
 * Merchant API client.
 *
 * <p>Signing, digests and body encryption are done by the SDK; callers hold the configuration
 * and build business requests, and never touch Signature-Input, Content-Digest or the envelope.
 *
 * <p>The default HTTP transport uses Apache HttpClient 5 without automatic retries or redirects.
 */
public final class Client implements AutoCloseable {

    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);
    private static final int DEFAULT_MAX_RESPONSE_BYTES = 8 << 20;
    static final int DEFAULT_MAX_CONNECTIONS = 50;
    private static final String DEFAULT_USER_AGENT = "merchant-sdk-java";
    private static final String DEFAULT_ACCEPT_LANGUAGE = "en-US";

    /** Sends one HTTP request; an implementation can replace the built-in HTTP transport. */
    @FunctionalInterface
    public interface Transport {
        /** Returns the HTTP status code and the raw response body. */
        Map.Entry<Integer, byte[]> send(
                String url, String method, Map<String, String> headers, byte[] body);
    }

    private final String baseUrl;
    private final String accessKey;
    private final byte[] merchantPrivateKey;
    private final String bodyKeyId;
    private final byte[] bodyPublicKey;
    private final Map<String, byte[]> webhookKeys;
    private final String userAgent;
    private final String acceptLanguage;
    private final int maxResponseBytes;
    private final Transport transport;
    private final boolean ownsTransport;
    private final java.util.concurrent.atomic.AtomicBoolean closed = new java.util.concurrent.atomic.AtomicBoolean();
    private final LongSupplier clock;

    private Client(Builder builder) {
        this.baseUrl = builder.baseUrl;
        this.accessKey = builder.accessKey;
        this.merchantPrivateKey = builder.merchantPrivateKey;
        this.bodyKeyId = builder.bodyKeyId;
        this.bodyPublicKey = builder.bodyPublicKey;
        this.webhookKeys = Collections8.mapCopy(builder.webhookKeys);
        this.userAgent = builder.userAgent;
        this.acceptLanguage = builder.acceptLanguage;
        this.maxResponseBytes = builder.maxResponseBytes;
        this.ownsTransport = builder.transport == null;
        this.transport = ownsTransport
                ? new HttpClientTransport(builder.timeout, builder.maxResponseBytes, builder.maxConnections) : builder.transport;
        this.clock = builder.clock;
    }

    /** Closes the SDK-owned connection pool; an injected transport remains owned by its caller. */
    @Override
    public void close() {
        closed.set(true);
        if (ownsTransport) ((HttpClientTransport) transport).close();
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Client configuration; a missing or invalid field makes build() throw
     * JoogopayException.Config.
     *
     * <p>baseUrl is scheme and host only, https; a path is rejected because the
     * SDK appends the endpoint path itself.
     *
     * <p>merchantPrivateKeyBase64 takes either form of Ed25519 private key: the
     * 32-byte seed libsodium and OpenSSL hand out, or the 64-byte seed plus
     * public key.
     *
     * <p>platformBodyKeyId names which platform key seals the request body and
     * travels in the envelope so the gateway knows which private key opens it; it
     * must name the key given in platformBodyPublicKeyBase64, which is X25519,
     * not the Ed25519 webhook key.
     *
     * <p>platformWebhookPublicKeys maps key id to platform Ed25519 public key and
     * verifies webhook signatures, the opposite direction. The webhook names its
     * key id, so this holds every key the platform may currently sign with;
     * during a rotation that is two. Required even without webhooks.
     */
    public static final class Builder {
        private String baseUrl;
        private String accessKey;
        private byte[] merchantPrivateKey;
        private String bodyKeyId;
        private byte[] bodyPublicKey;
        private final Map<String, byte[]> webhookKeys = new LinkedHashMap<>();
        private Duration timeout = DEFAULT_TIMEOUT;
        private String userAgent = DEFAULT_USER_AGENT;
        private String acceptLanguage = DEFAULT_ACCEPT_LANGUAGE;
        private int maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES;
        private int maxConnections = DEFAULT_MAX_CONNECTIONS;
        private Transport transport;
        private LongSupplier clock = () -> System.currentTimeMillis() / 1000L;

        private String rawBaseUrl;
        private String rawAccessKey;
        private String rawMerchantPrivateKey;
        private String rawBodyKeyId;
        private String rawBodyPublicKey;
        private Map<String, String> rawWebhookKeys = Collections8.map();

        public Builder baseUrl(String value) {
            this.rawBaseUrl = value;
            return this;
        }

        public Builder accessKey(String value) {
            this.rawAccessKey = value;
            return this;
        }

        public Builder merchantPrivateKeyBase64(String value) {
            this.rawMerchantPrivateKey = value;
            return this;
        }

        public Builder platformBodyKeyId(String value) {
            this.rawBodyKeyId = value;
            return this;
        }

        public Builder platformBodyPublicKeyBase64(String value) {
            this.rawBodyPublicKey = value;
            return this;
        }

        public Builder platformWebhookPublicKeys(Map<String, String> value) {
            this.rawWebhookKeys = value == null ? Collections8.map() : value;
            return this;
        }

        public Builder timeout(Duration value) {
            this.timeout = value;
            return this;
        }

        public Builder userAgent(String value) {
            this.userAgent = value;
            return this;
        }

        public Builder acceptLanguage(String value) {
            this.acceptLanguage = value;
            return this;
        }

        public Builder maxResponseBytes(int value) {
            this.maxResponseBytes = value;
            return this;
        }

        public Builder transport(Transport value) {
            this.transport = value;
            return this;
        }

        /** Limits total and per-route connections in the default transport; ignored by custom transports. */
        public Builder maxConnections(int value) {
            this.maxConnections = value;
            return this;
        }

        /** Overrides the clock used for signature timestamps. */
        public Builder clock(LongSupplier value) {
            this.clock = value;
            return this;
        }

        public Client build() {
            baseUrl = trimOrEmpty(rawBaseUrl);
            if (baseUrl.isEmpty()) {
                throw new JoogopayException.Config("sdk: baseUrl is required");
            }
            URI uri;
            try {
                uri = URI.create(baseUrl);
            } catch (IllegalArgumentException e) {
                throw new JoogopayException.Config("sdk: baseUrl must be an absolute origin URL");
            }
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                    || uri.getQuery() != null || uri.getFragment() != null) {
                throw new JoogopayException.Config("sdk: baseUrl must be an absolute origin URL");
            }
            String path = uri.getPath();
            if (path != null && !path.isEmpty() && !path.equals("/")) {
                throw new JoogopayException.Config("sdk: baseUrl must not contain a path");
            }
            while (baseUrl.endsWith("/")) {
                baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
            }

            accessKey = trimOrEmpty(rawAccessKey);
            if (accessKey.isEmpty()) {
                throw new JoogopayException.Config("sdk: accessKey is required");
            }
            merchantPrivateKey = decodeKey(rawMerchantPrivateKey, Collections8.list(32, 64),
                    "merchant Ed25519 private key");
            bodyKeyId = trimOrEmpty(rawBodyKeyId);
            if (bodyKeyId.isEmpty()) {
                throw new JoogopayException.Config("sdk: platformBodyKeyId is required");
            }
            bodyPublicKey = decodeKey(rawBodyPublicKey,
                    Collections8.list(Protocol.X25519_PUBLIC_KEY_SIZE), "platform X25519 public key");
            if (rawWebhookKeys.isEmpty()) {
                throw new JoogopayException.Config(
                        "sdk: platformWebhookPublicKeys is required");
            }
            rawWebhookKeys.forEach((keyId, value) -> {
                String id = trimOrEmpty(keyId);
                if (id.isEmpty()) {
                    throw new JoogopayException.Config(
                            "sdk: platform webhook key id must not be empty");
                }
                webhookKeys.put(id, decodeKey(value,
                        Collections8.list(Protocol.ED25519_PUBLIC_KEY_SIZE),
                        "platform webhook Ed25519 public key"));
            });

            if (maxResponseBytes <= 0 || maxResponseBytes == Integer.MAX_VALUE) {
                throw new JoogopayException.Config("sdk: maxResponseBytes must be between 1 and 2147483646");
            }
            if (maxConnections <= 0) {
                throw new JoogopayException.Config("sdk: maxConnections must be positive");
            }
            return new Client(this);
        }

        private static String trimOrEmpty(String value) {
            return value == null ? "" : value.trim();
        }

        private static byte[] decodeKey(String value, List<Integer> sizes, String what) {
            byte[] raw;
            try {
                raw = Base64.getDecoder().decode(trimOrEmpty(value));
            } catch (IllegalArgumentException e) {
                throw new JoogopayException.Config("sdk: invalid " + what);
            }
            if (!sizes.contains(raw.length)) {
                throw new JoogopayException.Config("sdk: invalid " + what);
            }
            return raw;
        }
    }

    public Map<String, Object> createPayment(Map<String, Object> request) {
        return createPayment(request, null);
    }

    public Map<String, Object> createPayment(Map<String, Object> request, String idempotencyKey) {
        validateCreateCommon(request);
        validateMethod(str(request, "currency"), mapOf(request, "paymentMethod"),
                Rules.PAYMENT_METHOD_RULES);
        return write("/api/v1/payments", request, idempotencyKey);
    }

    public Map<String, Object> createPayout(Map<String, Object> request) {
        return createPayout(request, null);
    }

    public Map<String, Object> createPayout(Map<String, Object> request, String idempotencyKey) {
        validateCreateCommon(request);
        validateMethod(str(request, "currency"), mapOf(request, "payoutMethod"),
                Rules.PAYOUT_METHOD_RULES);
        return write("/api/v1/payouts", request, idempotencyKey);
    }

    public Map<String, Object> supplementPayment(Map<String, Object> request) {
        return supplementPayment(request, null);
    }

    /**
     * Submits the payer's transfer reference ({@code tradeNo}) for a payment order that is still
     * PROCESSING so the platform can have the channel match it. Exactly one of {@code orderNo} or
     * {@code merchantOrderNo} locates the order. A successful response only means the channel
     * accepted the reference; the final status still arrives through the webhook or a query. The
     * tradeNo format is validated by the platform per currency, not here.
     */
    public Map<String, Object> supplementPayment(Map<String, Object> request, String idempotencyKey) {
        String orderNo = str(request, "orderNo").trim();
        String merchantOrderNo = str(request, "merchantOrderNo").trim();
        String tradeNo = str(request, "tradeNo").trim();
        if (tradeNo.isEmpty()) {
            throw new JoogopayException.Request("sdk: required field is empty: tradeNo");
        }
        if (orderNo.isEmpty() == merchantOrderNo.isEmpty()) {
            throw new JoogopayException.Request(
                    "sdk: exactly one of orderNo or merchantOrderNo is required");
        }
        LinkedHashMap<String, Object> body = new LinkedHashMap<String, Object>();
        if (!orderNo.isEmpty()) {
            body.put("orderNo", orderNo);
        } else {
            body.put("merchantOrderNo", merchantOrderNo);
        }
        body.put("tradeNo", tradeNo);
        return write("/api/v1/payments/trade-no", body, idempotencyKey);
    }

    public Map<String, Object> queryPaymentByOrderNo(String orderNo) {
        return read("/api/v1/payments", Collections8.map("orderNo", orderNo));
    }

    public Map<String, Object> queryPaymentByMerchantOrderNo(String merchantOrderNo) {
        return read("/api/v1/payments", Collections8.map("merchantOrderNo", merchantOrderNo));
    }

    public Map<String, Object> queryPayoutByOrderNo(String orderNo) {
        return read("/api/v1/payouts", Collections8.map("orderNo", orderNo));
    }

    public Map<String, Object> queryPayoutByMerchantOrderNo(String merchantOrderNo) {
        return read("/api/v1/payouts", Collections8.map("merchantOrderNo", merchantOrderNo));
    }

    public Map<String, Object> getPayoutReceipt(String orderNo) {
        String value = validatePathOrderNo(orderNo);
        return read("/api/v1/payouts/" + pathEscape(value) + "/receipt", Collections8.map());
    }

    public Map<String, Object> getBalance(String currency) {
        return read("/api/v1/balances", Collections8.map("currency", currency));
    }

    public Map<String, Object> getUsdRate(String currency, String payMethod) {
        return read("/api/v1/usd-rates", Collections8.map("currency", currency, "payMethod", payMethod));
    }

    /** Public hosted-checkout query: unsigned and unencrypted. */
    public Map<String, Object> getPaymentCheckout(String orderNo) {
        String url = baseUrl + "/api/v1/payment/checkout?orderNo=" + urlEncode(orderNo);
        return send(url, "GET", new LinkedHashMap<>(), null);
    }

    /**
     * Reports the upstream transaction reference (UTR) the payer entered on the hosted checkout
     * so the platform can match the transfer to the order. Unsigned and unencrypted, like
     * checkout.
     *
     * <p>No exception does not mean accepted: a refusal is also HTTP 200 with envelope code 200,
     * and the outcome is {@code data.status} (1 accepted, 0 refused with the reason in
     * {@code message}, e.g. rate limiting).
     */
    public Map<String, Object> submitPaymentTradeNo(String orderNo, String tradeNo) {
        String no = orderNo == null ? "" : orderNo.trim();
        String trade = tradeNo == null ? "" : tradeNo.trim();
        if (no.isEmpty() || trade.isEmpty()) {
            throw new JoogopayException.Request("sdk: invalid query parameter");
        }
        LinkedHashMap<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("orderNo", no);
        body.put("tradeNo", trade);
        return publicPost("/api/v1/payment/submitTradeNo", body);
    }

    /**
     * Completes the payer details of an order created without them; only then does the platform
     * submit the order to the channel. payMethod and extra may be omitted when the order already
     * carries them. Unsigned and unencrypted; {@code data.status} means the same as in
     * {@link #submitPaymentTradeNo}.
     */
    public Map<String, Object> addPaymentExtraInfo(String orderNo, String payMethod, Map<String, String> extra) {
        String no = orderNo == null ? "" : orderNo.trim();
        if (no.isEmpty()) {
            throw new JoogopayException.Request("sdk: invalid query parameter");
        }
        LinkedHashMap<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("orderNo", no);
        String method = payMethod == null ? "" : payMethod.trim();
        if (!method.isEmpty()) {
            body.put("payMethod", method);
        }
        if (extra != null && !extra.isEmpty()) {
            body.put("extra", extra);
        }
        return publicPost("/api/v1/payment/addExtraInfo", body);
    }

    /** Unauthenticated POST: plain JSON, unsigned and unencrypted. */
    private Map<String, Object> publicPost(String path, Map<String, Object> body) {
        LinkedHashMap<String, String> headers = new LinkedHashMap<String, String>();
        headers.put("Content-Type", "application/json");
        return send(baseUrl + path, "POST", headers, Json.write(body));
    }

    /** The pattern the gateway applies to order amounts, including the DECIMAL(18,2) bound. */
    private static final Pattern AMOUNT = Pattern.compile(Rules.AMOUNT_PATTERN);
    private static final Pattern NON_ZERO_DIGIT = Pattern.compile("[1-9]");

    private static boolean isEmptyValue(Object value) {
        return value == null || (value instanceof String && ((String) value).trim().isEmpty());
    }

    /**
     * Amounts are decimal strings; the gateway rejects JSON numbers. The pattern admits only
     * digits and a dot, so "greater than zero" reduces to "contains a non-zero digit".
     */
    private static void validateAmount(String field, Object value) {
        if (value == null || "".equals(value)) {
            throw new JoogopayException.Request("sdk: required field is empty: " + field);
        }
        if (!(value instanceof String)) {
            throw new JoogopayException.Request("sdk: " + field
                    + " must be a decimal string such as \"100.00\", got "
                    + value.getClass().getSimpleName());
        }
        String text = (String) value;
        if (!AMOUNT.matcher(text).matches()) {
            throw new JoogopayException.Request(
                    "sdk: " + field + " must be a positive decimal string: '" + text + "'");
        }
        if (!NON_ZERO_DIGIT.matcher(text).find()) {
            throw new JoogopayException.Request("sdk: " + field + " must be greater than 0");
        }
    }

    /** Mirrors the gateway rule: an absolute URL starting with https://. */
    private static void validateWebhookUrl(String field, Object value) {
        if (!(value instanceof String) || isEmptyValue(value)) {
            throw new JoogopayException.Request("sdk: required field is empty: " + field);
        }
        String text = (String) value;
        if (!text.toLowerCase(Locale.ROOT).startsWith(Rules.WEBHOOK_URL_PREFIX)) {
            String scheme = Rules.WEBHOOK_URL_PREFIX.replaceAll("://$", "");
            throw new JoogopayException.Request(
                    "sdk: " + field + " must be an absolute " + scheme + " URL");
        }
    }

    /**
     * The four top-level fields the gateway marks required. Failing here saves a signed and
     * encrypted round trip that would only end in INVALID_FIELD.
     */
    private static void validateCreateCommon(Map<String, Object> body) {
        Map<String, Object> b = body == null ? Collections8.map() : body;
        for (String field : Rules.CREATE_REQUIRED_TEXT_FIELDS) {
            if (isEmptyValue(b.get(field))) {
                throw new JoogopayException.Request("sdk: required field is empty: " + field);
            }
        }
        validateAmount("amount", b.get("amount"));
        validateWebhookUrl("webhookUrl", b.get("webhookUrl"));
    }

    /** The caller path-escapes the returned value before it enters the signature base. */
    private static String validatePathOrderNo(String orderNo) {
        String value = orderNo == null ? "" : orderNo.trim();
        if (value.isEmpty()) {
            throw new JoogopayException.Request("sdk: invalid path parameter");
        }
        return value;
    }

    private static String str(Map<String, Object> m, String key) {
        Object v = m == null ? null : m.get(key);
        return v == null ? "" : String.valueOf(v);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mapOf(Map<String, Object> m, String key) {
        Object v = m == null ? null : m.get(key);
        return v instanceof Map ? (Map<String, Object>) v : Collections8.map();
    }

    /**
     * Method-level pre-flight validation: extra shape and required extra fields, driven by the
     * generated {@link Rules} table shared by every SDK.
     *
     * <p>Format rules (phone length, e-mail, IFSC length, ...) are deliberately left to the
     * gateway: they evolve per currency and channel, a copy here would drift, and a wrong
     * rejection could only be fixed by an SDK release.
     */
    private void validateMethod(String currency, Map<String, Object> method, Map<String, Rules.Rule> rules) {
        String code = str(method, "code").trim();
        if (code.isEmpty()) {
            throw new JoogopayException.Request("sdk: method code is required");
        }

        java.util.ArrayList<String> present = new java.util.ArrayList<String>();
        for (Map.Entry<String, Object> e : method.entrySet()) {
            if (!"code".equals(e.getKey()) && e.getValue() != null) {
                present.add(e.getKey());
            }
        }
        java.util.Collections.sort(present);

        if (present.size() > 1) {
            throw new JoogopayException.Request(
                    "sdk: only one method extra may be set: " + String.join(", ", present));
        }
        String want = Rules.METHOD_EXTRA_FIELDS.get(code);
        if (present.size() == 1 && want != null && !present.get(0).equals(want)) {
            throw new JoogopayException.Request(String.format(
                    "sdk: method extra does not match code: %s expects '%s', got '%s'",
                    code, want, present.get(0)));
        }

        Rules.Rule rule = rules.get(currency == null ? "" : currency.trim().toUpperCase(Locale.ROOT));
        // unknown currency: leave it to the gateway, this table may be older than the gateway's
        if (rule == null) {
            return;
        }
        if (!rule.codes().isEmpty() && !rule.codes().contains(code)) {
            throw new JoogopayException.Request(
                    "sdk: method is not available for this currency: " + code + " for " + currency);
        }

        java.util.ArrayList<String> need = new java.util.ArrayList<>(rule.required());
        need.addAll(rule.byMethod().getOrDefault(code, Collections8.list()));
        List<String> optionalNullableStrings = rule.optionalNullableStringsByMethod().getOrDefault(code, Collections8.list());
        if (need.isEmpty() && optionalNullableStrings.isEmpty()) {
            return;
        }
        Map<String, Object> extra = present.isEmpty() ? Collections8.map() : mapOf(method, present.get(0));
        for (String field : need) {
            if (rule.allowEmpty().contains(field)) {
                if (!(extra.get(field) instanceof String)) {
                    throw new JoogopayException.Request(String.format(
                            "sdk: extra.%s must be a string for %s %s", field, currency, code));
                }
                continue;
            }
            if (isEmptyValue(extra.get(field))) {
                throw new JoogopayException.Request(String.format(
                        "sdk: required extra field is empty: extra.%s for %s %s", field, currency, code));
            }
        }
        for (String field : optionalNullableStrings) {
            Object value = extra.get(field);
            if (value != null && !(value instanceof String)) {
                throw new JoogopayException.Request(String.format(
                        "sdk: extra.%s must be a string or null for %s %s", field, currency, code));
            }
        }
    }

    /** Verifies a platform webhook: shape, digest, event id, freshness window and Ed25519 signature. */
    public Map<String, Object> verifyWebhook(
            String method, String path, Map<String, String> headers, byte[] body, String rawQuery) {
        if (method == null || !method.toUpperCase(Locale.ROOT).equals("POST")) {
            throw new JoogopayException.Webhook("sdk: webhook must be POST");
        }
        HashMap<String, String> lowered = new HashMap<String, String>();
        if (headers != null) {
            headers.forEach((k, v) -> lowered.put(k.toLowerCase(Locale.ROOT), v));
        }
        String contentType = lowered.getOrDefault("content-type", "").trim();
        if (!contentType.equals("application/json")) {
            throw new JoogopayException.Webhook(
                    "sdk: webhook Content-Type must be application/json");
        }
        if (body == null || body.length == 0 || body.length > Protocol.MAX_WIRE_BODY_BYTES) {
            throw new JoogopayException.Webhook("sdk: invalid webhook body size");
        }
        if (!Protocol.verifyContentDigest(
                body, lowered.get(Protocol.HEADER_CONTENT_DIGEST.toLowerCase(Locale.ROOT)))) {
            throw new JoogopayException.Webhook("sdk: webhook Content-Digest mismatch");
        }

        String eventId = lowered
                .getOrDefault(Protocol.HEADER_WEBHOOK_EVENT_ID.toLowerCase(Locale.ROOT), "").trim();
        Protocol.validateWebhookEventId(eventId);
        Map<String, Object> payload;
        try {
            payload = Json.readObject(body);
        } catch (RuntimeException e) {
            throw new JoogopayException.Webhook("sdk: invalid webhook body");
        }
        if (!eventId.equals(payload.get("eventId"))) {
            throw new JoogopayException.Webhook("sdk: webhook event id mismatch");
        }

        Protocol.SignatureParams params = Protocol.parsePlatformSignatureInput(
                lowered.getOrDefault(Protocol.HEADER_SIGNATURE_INPUT.toLowerCase(Locale.ROOT), ""));
        Protocol.validateSignatureParams(params, clock.getAsLong());
        byte[] publicKey = webhookKeys.get(params.keyId());
        if (publicKey == null) {
            throw new JoogopayException.Webhook("sdk: webhook platform key not found");
        }

        byte[] signature = Protocol.parseSignature(
                lowered.getOrDefault(Protocol.HEADER_SIGNATURE.toLowerCase(Locale.ROOT), ""),
                Protocol.SIGNATURE_LABEL_PLATFORM);
        byte[] base = Protocol.signatureBase(params, "POST", path, rawQuery, headers);
        Protocol.verifyEd25519(publicKey, base, signature);
        return payload;
    }

    public Map<String, Object> parsePaymentWebhook(
            String method, String path, Map<String, String> headers, byte[] body) {
        return parsePaymentWebhook(method, path, headers, body, "");
    }

    /** rawQuery is the query string exactly as received: no leading "?" and not re-encoded. */
    public Map<String, Object> parsePaymentWebhook(
            String method, String path, Map<String, String> headers, byte[] body, String rawQuery) {
        return requireWebhookFields(verifyWebhook(method, path, headers, body, rawQuery),
                Status.WEBHOOK_ORDER_TYPE_PAYMENT);
    }

    public Map<String, Object> parsePayoutWebhook(
            String method, String path, Map<String, String> headers, byte[] body) {
        return parsePayoutWebhook(method, path, headers, body, "");
    }

    /** rawQuery is the query string exactly as received: no leading "?" and not re-encoded. */
    public Map<String, Object> parsePayoutWebhook(
            String method, String path, Map<String, String> headers, byte[] body, String rawQuery) {
        return requireWebhookFields(verifyWebhook(method, path, headers, body, rawQuery),
                Status.WEBHOOK_ORDER_TYPE_PAYOUT);
    }

    private static Map<String, Object> requireWebhookFields(
            Map<String, Object> payload, String orderType) {
        if (isBlank(payload.get("eventId"))
                || !orderType.equals(payload.get("orderType"))
                || isBlank(payload.get("orderNo"))
                || isBlank(payload.get("merchantOrderNo"))
                || isBlank(payload.get("status"))) {
            throw new JoogopayException.Webhook("sdk: invalid webhook body");
        }
        return payload;
    }

    private static boolean isBlank(Object value) {
        return !(value instanceof String) || ((String) value).isEmpty();
    }

    private Map<String, Object> write(String path, Map<String, Object> body, String idempotencyKey) {
        String url = baseUrl + path;
        byte[] wireBody;
        Map<String, String> headers;
        try {
            String key = idempotencyKey == null || idempotencyKey.codePoints().allMatch(Character::isWhitespace)
                    ? Protocol.newNonce()
                    : idempotencyKey.trim();
            Protocol.validateIdempotencyKey(key);

            wireBody = Protocol.sealBodyEnvelope(Json.write(body), bodyPublicKey, bodyKeyId);
            Protocol.SignatureParams params = Protocol.newMerchantWriteSignatureParams(
                    Protocol.newNonce(), clock.getAsLong());

            LinkedHashMap<String, String> built = new LinkedHashMap<String, String>();
            built.put("Content-Type", "application/json");
            built.put(Protocol.HEADER_CONTENT_ENCRYPTION, Protocol.CONTENT_ENCRYPTION);
            built.put(Protocol.HEADER_CONTENT_DIGEST, Protocol.contentDigestSha256(wireBody));
            built.put(Protocol.HEADER_IDEMPOTENCY_KEY, key);
            built.put(Protocol.HEADER_MERCHANT_ACCESS_KEY, accessKey);
            built.put(Protocol.HEADER_SIGNATURE_INPUT, Protocol.signatureInputHeader(params));
            byte[] base = Protocol.signatureBase(params, "POST", path, "", built);
            built.put(Protocol.HEADER_SIGNATURE, Protocol.signEd25519(
                    merchantPrivateKey, Protocol.SIGNATURE_LABEL_MERCHANT, base));
            headers = built;
        } catch (JoogopayException.Protocol e) {
            // Sealing and signing happen before the request is sent.
            throw new JoogopayException.Request("sdk: build signed request: " + e.getMessage(), e);
        }

        return send(url, "POST", headers, wireBody);
    }

    private Map<String, Object> read(String path, Map<String, String> query) {
        StringBuilder encoded = new StringBuilder();
        query.forEach((key, value) -> {
            if (value == null || value.trim().isEmpty()) {
                throw new JoogopayException.Request("sdk: invalid query parameter: " + key);
            }
            if (encoded.length() > 0) {
                encoded.append('&');
            }
            encoded.append(urlEncode(key)).append('=').append(urlEncode(value));
        });
        String rawQuery = encoded.toString();
        String url = baseUrl + path + (rawQuery.isEmpty() ? "" : "?" + rawQuery);

        Map<String, String> headers;
        try {
            Protocol.validateMerchantReadQuery(rawQuery);
            Protocol.SignatureParams params = Protocol.newMerchantReadSignatureParams(
                    Protocol.newNonce(), clock.getAsLong());

            LinkedHashMap<String, String> built = new LinkedHashMap<String, String>();
            built.put(Protocol.HEADER_MERCHANT_ACCESS_KEY, accessKey);
            built.put(Protocol.HEADER_SIGNATURE_INPUT, Protocol.signatureInputHeader(params));
            byte[] base = Protocol.signatureBase(params, "GET", path, rawQuery, built);
            built.put(Protocol.HEADER_SIGNATURE, Protocol.signEd25519(
                    merchantPrivateKey, Protocol.SIGNATURE_LABEL_MERCHANT, base));
            headers = built;
        } catch (JoogopayException.Protocol e) {
            // Signing happens before the request is sent.
            throw new JoogopayException.Request("sdk: build signed request: " + e.getMessage(), e);
        }

        return send(url, "GET", headers, null);
    }

    private Map<String, Object> send(String url, String method, Map<String, String> headers, byte[] body) {
        if (closed.get()) throw new JoogopayException.Request("sdk: client is closed");
        LinkedHashMap<String, String> all = new LinkedHashMap<>(headers);
        all.put("Accept", "application/json");
        all.put("Accept-Language", acceptLanguage);
        all.put("User-Agent", userAgent);
        Map.Entry<Integer, byte[]> response = transport.send(url, method, all, body);
        return decode(response.getKey(), response.getValue());
    }

    /** Returns the envelope's data object; a success envelope that carries none is a Response failure. */
    @SuppressWarnings("unchecked")
    private Map<String, Object> decode(int httpStatus, byte[] raw) {
        if (raw.length > maxResponseBytes) {
            throw new JoogopayException.ResponseTooLarge(
                    "sdk: response body exceeds maxResponseBytes");
        }
        Map<String, Object> envelope;
        try {
            envelope = Json.readObject(raw);
        } catch (RuntimeException e) {
            throw new JoogopayException.Response(httpStatus, raw);
        }
        Object code = envelope.get("code");
        int codeValue = code instanceof Number ? ((Number) code).intValue() : 0;
        // HTTP 200 with a non-200 envelope code is still a business failure
        if (httpStatus != 200 || codeValue != 200) {
            Object data = envelope.get("data");
            String message = data instanceof Map<?, ?> && ((Map<?, ?>) data).get("message") instanceof String
                    ? (String) ((Map<?, ?>) data).get("message") : "";
            throw new JoogopayException.Api(
                    httpStatus, codeValue,
                    envelope.get("msg") instanceof String ? (String) envelope.get("msg") : "",
                    message,
                    envelope.get("traceId") instanceof String ? (String) envelope.get("traceId") : "",
                    raw);
        }
        // A success envelope always carries the business object; an empty map would
        // let a caller record an order that has no orderNo as successful.
        if (!(envelope.get("data") instanceof Map<?, ?>)) {
            throw new JoogopayException.Response(httpStatus, raw);
        }
        return (Map<String, Object>) envelope.get("data");
    }

    private static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (java.io.UnsupportedEncodingException impossible) {
            throw new AssertionError(impossible);
        }
    }

    /** URLEncoder encodes a space as "+"; a path segment carries it as %20. */
    private static String pathEscape(String value) {
        return urlEncode(value).replace("+", "%20");
    }

    static final class HttpClientTransport implements Transport, AutoCloseable {
        private final int timeoutMillis;
        private final int maxResponseBytes;
        private final CloseableHttpClient client;
        private final java.util.Set<HttpUriRequestBase> active = new java.util.HashSet<>();
        private boolean closing;
        private boolean terminated;
        private IOException closeFailure;

        HttpClientTransport(Duration timeout, int maxResponseBytes) {
            this(timeout, maxResponseBytes, DEFAULT_MAX_CONNECTIONS);
        }

        HttpClientTransport(Duration timeout, int maxResponseBytes, int maxConnections) {
            if (maxConnections <= 0) {
                throw new JoogopayException.Config("sdk: maxConnections must be positive");
            }
            long millis;
            try {
                millis = (timeout == null ? DEFAULT_TIMEOUT : timeout).toMillis();
            } catch (ArithmeticException e) {
                throw new JoogopayException.Config("sdk: timeout is too large");
            }
            if (millis <= 0 || millis > Integer.MAX_VALUE) {
                throw new JoogopayException.Config("sdk: timeout must be between 1 ms and 2147483647 ms");
            }
            this.timeoutMillis = (int) millis;
            this.maxResponseBytes = maxResponseBytes;
            Timeout limit = Timeout.ofMilliseconds(timeoutMillis);
            RequestConfig config = RequestConfig.custom()
                    .setConnectTimeout(limit).setConnectionRequestTimeout(limit).setResponseTimeout(limit)
                    .setAuthenticationEnabled(false).build();
            client = HttpClients.custom().useSystemProperties().setDefaultRequestConfig(config)
                    .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create().useSystemProperties()
                            .setMaxConnTotal(maxConnections).setMaxConnPerRoute(maxConnections).build())
                    .disableAutomaticRetries().disableRedirectHandling().disableCookieManagement()
                    .disableContentCompression().build();
        }

        @Override
        public Map.Entry<Integer, byte[]> send(
                String url, String method, Map<String, String> headers, byte[] body) {
            HttpUriRequestBase request;
            try {
                request = new HttpUriRequestBase(method, URI.create(url));
                for (Map.Entry<String, String> header : headers.entrySet()) {
                    if (header.getKey().indexOf('\r') >= 0 || header.getKey().indexOf('\n') >= 0
                            || header.getValue().indexOf('\r') >= 0 || header.getValue().indexOf('\n') >= 0) {
                        throw new IllegalArgumentException("invalid header");
                    }
                    request.setHeader(header.getKey(), header.getValue());
                }
                if (body != null) request.setEntity(new ByteArrayEntity(
                        body, (ContentType) null));
            } catch (IllegalArgumentException e) {
                throw new JoogopayException.Request("sdk: build http request: " + e.getMessage(), e);
            }
            synchronized (active) {
                if (closing) throw new JoogopayException.Request("sdk: client is closed");
                active.add(request);
            }
            try {
                return client.execute(request, response -> {
                    if (response.getEntity() == null) return Collections8.entry(response.getCode(), new byte[0]);
                    try (InputStream input = response.getEntity().getContent();
                         ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                        byte[] buffer = new byte[8192];
                        int remaining = maxResponseBytes + 1;
                        while (remaining > 0) {
                            int count = input.read(buffer, 0, Math.min(buffer.length, remaining));
                            if (count == -1) break;
                            output.write(buffer, 0, count);
                            remaining -= count;
                            if (remaining == 0) {
                                request.cancel();
                                throw new JoogopayException.ResponseTooLarge("sdk: response body exceeds maxResponseBytes");
                            }
                        }
                        return Collections8.entry(response.getCode(), output.toByteArray());
                    }
                });
            } catch (IOException e) {
                throw new JoogopayException.Transport("sdk: http request failed: " + e.getMessage(), e);
            } finally {
                synchronized (active) {
                    active.remove(request);
                    active.notifyAll();
                }
            }
        }

        @Override
        public void close() {
            java.util.List<HttpUriRequestBase> pending;
            synchronized (active) {
                if (closing) {
                    awaitStopped(true);
                    if (closeFailure != null) throw new JoogopayException.Transport("sdk: close failed", closeFailure);
                    return;
                }
                closing = true;
                pending = new java.util.ArrayList<>(active);
            }
            for (HttpUriRequestBase request : pending) request.cancel();
            IOException failure = null;
            try {
                client.close();
            } catch (IOException e) {
                failure = e;
            } finally {
                synchronized (active) {
                    closeFailure = failure;
                    try {
                        awaitStopped(false);
                    } finally {
                        terminated = true;
                        active.notifyAll();
                    }
                }
            }
            if (closeFailure != null) throw new JoogopayException.Transport("sdk: close failed", closeFailure);
        }

        private void awaitStopped(boolean waitForCloser) {
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5);
            boolean interrupted = false;
            try {
                while (waitForCloser ? !terminated : !active.isEmpty()) {
                    long remaining = deadline - System.nanoTime();
                    if (remaining <= 0) {
                        closeFailure = new IOException("active HTTP requests did not stop while closing");
                        throw new JoogopayException.Transport("sdk: close failed", closeFailure);
                    }
                    try {
                        java.util.concurrent.TimeUnit.NANOSECONDS.timedWait(active, remaining);
                    } catch (InterruptedException e) {
                        interrupted = true;
                    }
                }
            } finally {
                if (interrupted) Thread.currentThread().interrupt();
            }
        }
    }
}
