package com.joogopay.sdk;

import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

/** Single JSON entry point; keeps Jackson out of the rest of the SDK. */
final class Json {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Json() {
    }

    static byte[] write(Object value) {
        try {
            return MAPPER.writeValueAsBytes(value);
        } catch (Exception e) {
            throw new JoogopayException.Request("sdk: marshal request body", e);
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> readObject(byte[] raw) {
        try {
            Object parsed = MAPPER.readValue(raw, Object.class);
            if (!(parsed instanceof Map)) {
                throw new IllegalArgumentException("not a json object");
            }
            return (Map<String, Object>) parsed;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid json", e);
        }
    }
}
