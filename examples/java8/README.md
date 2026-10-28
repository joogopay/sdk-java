# Java 8 protocol adapter

Use the full Java SDK on Java 8+, or copy `ProtocolAdapter.java` into an existing Java 8+ application and add your package declaration. This adapter handles request signing, POST encryption and webhook verification; keep your existing HTTP client and JSON library. It does not depend on the platform SDK.

The example uses `org.bouncycastle:bcprov-jdk18on:1.86` through its lightweight API: no native library, no global provider registration. Select an approved dependency version and review the adapter's sealed-box assembly and HSalsa20 derivation. Other compatible crypto implementations are allowed; changing libraries must preserve the wire protocol. JDK 8 and 17 alone do not provide the complete sealed-box construction. The complete SDK also supports Java 8; this adapter is for applications implementing their own client.

## Offline check

Supply an approved bcprov jar; the check does not download dependencies or contact the API:

```sh
BC_JAR=/path/to/bcprov-jdk18on-1.86.jar bash check.sh
# Optional: JAVA=/path/to/java8/bin/java JAVAC=/path/to/jdk/bin/javac
```

The check compares fixed signatures, opens reference ciphertext, tests randomized encryption and rejects malformed, stale and modified webhooks. All keys in the check are public test vectors. They must never be used for real requests. Compilation errors stop the check, and temporary classes are removed on exit. Use the [protocol vectors](protocol/testdata/) to validate an alternative implementation.

## Requests

Construct one `ProtocolAdapter` per merchant with its access key and signing private key, the platform body key id/public key, and the platform webhook key map. The merchant generates and keeps its private key; only its public key is registered with the platform. Private keys accept PKCS#8 PEM, base64 32-byte seeds or base64 64-byte seed/public-key pairs.

```java
ProtocolAdapter auth = new ProtocolAdapter(accessKey, merchantPrivateKey,
        platformBodyKeyId, platformBodyPublicKey, platformWebhookKeys);
ProtocolAdapter.SignedRequest read = auth.signRead("/api/v1/balances", "currency=BRL");
ProtocolAdapter.SignedRequest write = auth.signWrite("/api/v1/payments", businessJsonBytes);
```

Send every returned header and the exact `write.body` bytes. Do not serialize the envelope again or add `charset` to `Content-Type`. Sign the final encoded GET query exactly as sent. Regenerate the signature on every HTTP attempt, keep the original `merchantOrderNo` during recovery, and query before retrying an unknown outcome. See [strict wire rules](protocol/signature.md).

## Webhooks

```java
ProtocolAdapter.VerifiedWebhook event = auth.verifyWebhook(
        receivedPath, receivedRawQuery, receivedHeaders, receivedBodyBytes);
```

Map `SecurityException` to authentication rejection. Parse `event.json` with your JSON library, reject duplicate keys and require its top-level `eventId` to equal `event.eventId`. Preserve and validate single-valued signed headers before converting your framework's header collection to a map.

Before processing an event, match its platform `orderNo` to the order saved from creation under the expected merchant. Check order type, merchant order number, currency and the applicable amounts. For an unknown `orderNo`, durably queue the event and query it using that merchant's own credentials before changing balances or order state. A signed webhook or a matching `merchantOrderNo` alone does not establish order ownership. Callback URL routing is not an ownership check.

Deduplicate by `eventId` and make state transitions idempotent by the verified order. Commit the update or durably enqueue the event before returning 2xx. Queue failures return non-2xx; queued work must have its own retries. See [webhook processing](protocol/webhook.md). Start online validation with a balance query, then exercise create/query/callback/retry flows in the test environment.
