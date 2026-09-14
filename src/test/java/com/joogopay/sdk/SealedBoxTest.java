package com.joogopay.sdk;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import org.junit.jupiter.api.Test;

/**
 * Guards the sealed box assembly: the vector ciphertext comes from the reference implementation
 * (NaCl box), and failing to open it means the BouncyCastle primitives are wired up wrong.
 */
class SealedBoxTest {

    private static final Path VECTOR =
            Path.of("protocol", "testdata", "bodycrypt", "001-sealed-box.json");

    /** Plain string scan so this test does not depend on the SDK's JSON layer. */
    private static String field(String json, String name) {
        var marker = "\"" + name + "\"";
        int at = json.indexOf(marker);
        assertTrue(at >= 0, "vector missing field: " + name);
        int start = json.indexOf('"', json.indexOf(':', at) ) + 1;
        int end = json.indexOf('"', start);
        return json.substring(start, end);
    }

    @Test
    void opensCiphertextProducedByOtherLanguages() throws Exception {
        var json = Files.readString(VECTOR, StandardCharsets.UTF_8);
        var decoder = Base64.getDecoder();

        byte[] publicKey = decoder.decode(field(json, "platformBodyPublicKeyBase64"));
        byte[] privateKey = decoder.decode(field(json, "platformBodyPrivateKeyBase64"));
        byte[] wantPlaintext = decoder.decode(field(json, "plaintextBase64"));
        byte[] sealed = decoder.decode(field(json, "ciphertext"));

        byte[] got = SealedBox.sealOpen(sealed, publicKey, privateKey);
        assertArrayEquals(wantPlaintext, got, "must open to the vector plaintext");
        assertTrue(new String(got, StandardCharsets.UTF_8).contains("merchantOrderNo"));
    }

    @Test
    void roundTrips() throws Exception {
        var json = Files.readString(VECTOR, StandardCharsets.UTF_8);
        var decoder = Base64.getDecoder();
        byte[] publicKey = decoder.decode(field(json, "platformBodyPublicKeyBase64"));
        byte[] privateKey = decoder.decode(field(json, "platformBodyPrivateKeyBase64"));
        byte[] plaintext = "{\"amount\":\"100.00\"}".getBytes(StandardCharsets.UTF_8);

        byte[] sealed = SealedBox.seal(plaintext, publicKey);
        assertEquals(plaintext.length + SealedBox.SEAL_BYTES, sealed.length);
        assertArrayEquals(plaintext, SealedBox.sealOpen(sealed, publicKey, privateKey));
    }

    @Test
    void rejectsTamperedCiphertext() throws Exception {
        var json = Files.readString(VECTOR, StandardCharsets.UTF_8);
        var decoder = Base64.getDecoder();
        byte[] publicKey = decoder.decode(field(json, "platformBodyPublicKeyBase64"));
        byte[] privateKey = decoder.decode(field(json, "platformBodyPrivateKeyBase64"));
        byte[] sealed = decoder.decode(field(json, "ciphertext"));

        sealed[sealed.length - 1] ^= 0x01;
        assertThrows(IllegalStateException.class,
                () -> SealedBox.sealOpen(sealed, publicKey, privateKey));
    }
}
