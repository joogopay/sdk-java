package com.joogopay.sdk;

import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

/**
 * Pure-Java NaCl sealed box (libsodium's crypto_box_seal).
 *
 * <p>The JDK lacks XSalsa20-Poly1305, HSalsa20 and variable-length Blake2b, so the construction
 * is assembled from BouncyCastle primitives; it interoperates with libsodium's crypto_box_seal.
 *
 * <p>Correctness is guarded by the sealed-box vector under protocol/testdata/bodycrypt: its
 * ciphertext comes from the reference implementation (NaCl box) and opens to the expected plaintext.
 *
 * <p>Layout, identical to libsodium:
 * <pre>
 *   ephemeral_pk = X25519 ephemeral public key (32 bytes)
 *   nonce        = Blake2b-192(ephemeral_pk || recipient_pk)      24 bytes
 *   shared       = X25519(ephemeral_sk, recipient_pk)             32 bytes
 *   key          = HSalsa20(shared, 0^16)                         crypto_box_beforenm
 *   sealed       = ephemeral_pk || XSalsa20Poly1305(msg, nonce, key)
 * </pre>
 */
final class SealedBox {

    static final int PUBLIC_KEY_BYTES = 32;
    static final int SECRET_KEY_BYTES = 32;
    static final int NONCE_BYTES = 24;
    static final int MAC_BYTES = 16;
    static final int SEAL_BYTES = PUBLIC_KEY_BYTES + MAC_BYTES;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] SIGMA = "expand 32-byte k".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    private SealedBox() {
    }

    /** Returns ephemeral_pk || ciphertext for the recipient's X25519 public key. */
    static byte[] seal(byte[] plaintext, byte[] recipientPublicKey) {
        if (recipientPublicKey == null || recipientPublicKey.length != PUBLIC_KEY_BYTES) {
            throw new IllegalArgumentException("recipient public key must be 32 bytes");
        }
        var generator = new X25519KeyPairGenerator();
        generator.init(new X25519KeyGenerationParameters(RANDOM));
        var pair = generator.generateKeyPair();
        byte[] ephemeralPk = ((X25519PublicKeyParameters) pair.getPublic()).getEncoded();
        var ephemeralSk = (X25519PrivateKeyParameters) pair.getPrivate();

        byte[] nonce = sealNonce(ephemeralPk, recipientPublicKey);
        byte[] key = beforeNm(sharedSecret(ephemeralSk.getEncoded(), recipientPublicKey));

        byte[] boxed = secretBox(plaintext, nonce, key);
        byte[] sealed = new byte[ephemeralPk.length + boxed.length];
        System.arraycopy(ephemeralPk, 0, sealed, 0, ephemeralPk.length);
        System.arraycopy(boxed, 0, sealed, ephemeralPk.length, boxed.length);
        Arrays.fill(key, (byte) 0);
        return sealed;
    }

    /** Opens ephemeral_pk || ciphertext with the recipient's key pair. */
    static byte[] sealOpen(byte[] sealed, byte[] recipientPublicKey, byte[] recipientPrivateKey) {
        if (sealed == null || sealed.length < SEAL_BYTES) {
            throw new IllegalArgumentException("sealed box too short");
        }
        if (recipientPublicKey == null || recipientPublicKey.length != PUBLIC_KEY_BYTES
                || recipientPrivateKey == null || recipientPrivateKey.length != SECRET_KEY_BYTES) {
            throw new IllegalArgumentException("recipient key pair must be 32 bytes each");
        }
        byte[] ephemeralPk = Arrays.copyOfRange(sealed, 0, PUBLIC_KEY_BYTES);
        byte[] boxed = Arrays.copyOfRange(sealed, PUBLIC_KEY_BYTES, sealed.length);

        byte[] nonce = sealNonce(ephemeralPk, recipientPublicKey);
        byte[] key = beforeNm(sharedSecret(recipientPrivateKey, ephemeralPk));
        try {
            return secretBoxOpen(boxed, nonce, key);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private static byte[] sealNonce(byte[] ephemeralPk, byte[] recipientPk) {
        var digest = new Blake2bDigest(NONCE_BYTES * 8);
        digest.update(ephemeralPk, 0, ephemeralPk.length);
        digest.update(recipientPk, 0, recipientPk.length);
        byte[] nonce = new byte[NONCE_BYTES];
        digest.doFinal(nonce, 0);
        return nonce;
    }

    private static byte[] sharedSecret(byte[] privateKey, byte[] publicKey) {
        var agreement = new X25519Agreement();
        agreement.init(new X25519PrivateKeyParameters(privateKey, 0));
        byte[] shared = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(new X25519PublicKeyParameters(publicKey, 0), shared, 0);
        return shared;
    }

    /**
     * crypto_box_beforenm = HSalsa20(shared, 0^16). XSalsa20Engine runs HSalsa20 internally but
     * never exposes the subkey, so it is computed directly.
     */
    private static byte[] beforeNm(byte[] shared) {
        return HSalsa20.derive(shared, new byte[16], SIGMA);
    }

    /** crypto_secretbox_xsalsa20poly1305; output is tag || ciphertext. */
    private static byte[] secretBox(byte[] plaintext, byte[] nonce, byte[] key) {
        var engine = new XSalsa20Engine();
        engine.init(true, new ParametersWithIV(new KeyParameter(key), nonce));

        // NaCl convention: the first 32 keystream bytes are the Poly1305 one-time key;
        // the plaintext is encrypted from keystream offset 32 onwards
        byte[] subKey = new byte[32];
        engine.processBytes(new byte[32], 0, 32, subKey, 0);

        byte[] ciphertext = new byte[plaintext.length];
        engine.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);

        var poly = new Poly1305();
        poly.init(new KeyParameter(subKey));
        poly.update(ciphertext, 0, ciphertext.length);
        byte[] tag = new byte[MAC_BYTES];
        poly.doFinal(tag, 0);

        byte[] out = new byte[MAC_BYTES + ciphertext.length];
        System.arraycopy(tag, 0, out, 0, MAC_BYTES);
        System.arraycopy(ciphertext, 0, out, MAC_BYTES, ciphertext.length);
        Arrays.fill(subKey, (byte) 0);
        return out;
    }

    private static byte[] secretBoxOpen(byte[] boxed, byte[] nonce, byte[] key) {
        if (boxed.length < MAC_BYTES) {
            throw new IllegalArgumentException("ciphertext too short");
        }
        var engine = new XSalsa20Engine();
        engine.init(false, new ParametersWithIV(new KeyParameter(key), nonce));

        byte[] subKey = new byte[32];
        engine.processBytes(new byte[32], 0, 32, subKey, 0);

        byte[] tag = Arrays.copyOfRange(boxed, 0, MAC_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(boxed, MAC_BYTES, boxed.length);

        var poly = new Poly1305();
        poly.init(new KeyParameter(subKey));
        poly.update(ciphertext, 0, ciphertext.length);
        byte[] expected = new byte[MAC_BYTES];
        poly.doFinal(expected, 0);
        Arrays.fill(subKey, (byte) 0);

        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(tag, expected)) {
            throw new IllegalStateException("sealed box authentication failed");
        }
        byte[] plaintext = new byte[ciphertext.length];
        engine.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
        return plaintext;
    }
}
