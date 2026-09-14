package com.joogopay.sdk;

/**
 * HSalsa20, the function NaCl uses to derive the crypto_box symmetric key from an X25519 shared
 * secret (crypto_box_beforenm).
 *
 * <p>Neither the JDK nor BouncyCastle exposes it. It is the Salsa20 core without the final
 * addition, emitting eight state words (x0 x5 x10 x15 x6 x7 x8 x9); see D. J. Bernstein,
 * "Extending the Salsa20 nonce", section 2.
 *
 * <p>Correctness is guarded by the sealed-box vector under protocol/testdata/bodycrypt: a wrong
 * derivation cannot open ciphertext produced by the reference implementation (NaCl box).
 */
final class HSalsa20 {

    private static final int ROUNDS = 20;

    private HSalsa20() {
    }

    static byte[] derive(byte[] key, byte[] nonce, byte[] sigma) {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("HSalsa20 key must be 32 bytes");
        }
        if (nonce == null || nonce.length != 16) {
            throw new IllegalArgumentException("HSalsa20 nonce must be 16 bytes");
        }

        int[] x = new int[16];
        x[0] = le32(sigma, 0);
        x[5] = le32(sigma, 4);
        x[10] = le32(sigma, 8);
        x[15] = le32(sigma, 12);
        x[1] = le32(key, 0);
        x[2] = le32(key, 4);
        x[3] = le32(key, 8);
        x[4] = le32(key, 12);
        x[11] = le32(key, 16);
        x[12] = le32(key, 20);
        x[13] = le32(key, 24);
        x[14] = le32(key, 28);
        x[6] = le32(nonce, 0);
        x[7] = le32(nonce, 4);
        x[8] = le32(nonce, 8);
        x[9] = le32(nonce, 12);

        for (int i = 0; i < ROUNDS; i += 2) {
            // column round
            x[4] ^= rotl(x[0] + x[12], 7);
            x[8] ^= rotl(x[4] + x[0], 9);
            x[12] ^= rotl(x[8] + x[4], 13);
            x[0] ^= rotl(x[12] + x[8], 18);

            x[9] ^= rotl(x[5] + x[1], 7);
            x[13] ^= rotl(x[9] + x[5], 9);
            x[1] ^= rotl(x[13] + x[9], 13);
            x[5] ^= rotl(x[1] + x[13], 18);

            x[14] ^= rotl(x[10] + x[6], 7);
            x[2] ^= rotl(x[14] + x[10], 9);
            x[6] ^= rotl(x[2] + x[14], 13);
            x[10] ^= rotl(x[6] + x[2], 18);

            x[3] ^= rotl(x[15] + x[11], 7);
            x[7] ^= rotl(x[3] + x[15], 9);
            x[11] ^= rotl(x[7] + x[3], 13);
            x[15] ^= rotl(x[11] + x[7], 18);

            // row round
            x[1] ^= rotl(x[0] + x[3], 7);
            x[2] ^= rotl(x[1] + x[0], 9);
            x[3] ^= rotl(x[2] + x[1], 13);
            x[0] ^= rotl(x[3] + x[2], 18);

            x[6] ^= rotl(x[5] + x[4], 7);
            x[7] ^= rotl(x[6] + x[5], 9);
            x[4] ^= rotl(x[7] + x[6], 13);
            x[5] ^= rotl(x[4] + x[7], 18);

            x[11] ^= rotl(x[10] + x[9], 7);
            x[8] ^= rotl(x[11] + x[10], 9);
            x[9] ^= rotl(x[8] + x[11], 13);
            x[10] ^= rotl(x[9] + x[8], 18);

            x[12] ^= rotl(x[15] + x[14], 7);
            x[13] ^= rotl(x[12] + x[15], 9);
            x[14] ^= rotl(x[13] + x[12], 13);
            x[15] ^= rotl(x[14] + x[13], 18);
        }

        // unlike Salsa20 there is no final x += input; the eight words are taken as they are
        byte[] out = new byte[32];
        putLe32(out, 0, x[0]);
        putLe32(out, 4, x[5]);
        putLe32(out, 8, x[10]);
        putLe32(out, 12, x[15]);
        putLe32(out, 16, x[6]);
        putLe32(out, 20, x[7]);
        putLe32(out, 24, x[8]);
        putLe32(out, 28, x[9]);
        return out;
    }

    private static int rotl(int value, int bits) {
        return (value << bits) | (value >>> (32 - bits));
    }

    private static int le32(byte[] data, int offset) {
        return (data[offset] & 0xff)
                | ((data[offset + 1] & 0xff) << 8)
                | ((data[offset + 2] & 0xff) << 16)
                | ((data[offset + 3] & 0xff) << 24);
    }

    private static void putLe32(byte[] out, int offset, int value) {
        out[offset] = (byte) value;
        out[offset + 1] = (byte) (value >>> 8);
        out[offset + 2] = (byte) (value >>> 16);
        out[offset + 3] = (byte) (value >>> 24);
    }
}
