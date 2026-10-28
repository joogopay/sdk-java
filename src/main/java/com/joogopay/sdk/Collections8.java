package com.joogopay.sdk;

import java.util.*;

final class Collections8 {
    private Collections8() {}

    @SafeVarargs
    static <T> List<T> list(T... values) {
        List<T> out = new ArrayList<T>(values.length);
        for (T value : values) out.add(Objects.requireNonNull(value));
        return Collections.unmodifiableList(out);
    }

    @SafeVarargs
    static <T> Set<T> set(T... values) {
        Set<T> out = new LinkedHashSet<T>();
        for (T value : values) {
            if (!out.add(Objects.requireNonNull(value))) throw new IllegalArgumentException("duplicate element");
        }
        return Collections.unmodifiableSet(out);
    }

    @SuppressWarnings("unchecked")
    static <K, V> Map<K, V> map(Object... pairs) {
        if (pairs.length % 2 != 0) throw new IllegalArgumentException("odd key/value count");
        Map<K, V> out = new LinkedHashMap<K, V>();
        for (int i = 0; i < pairs.length; i += 2) {
            K key = (K) Objects.requireNonNull(pairs[i]);
            V value = (V) Objects.requireNonNull(pairs[i + 1]);
            if (out.containsKey(key)) throw new IllegalArgumentException("duplicate key");
            out.put(key, value);
        }
        return Collections.unmodifiableMap(out);
    }

    static <K, V> Map.Entry<K, V> entry(K key, V value) {
        return new AbstractMap.SimpleImmutableEntry<K, V>(Objects.requireNonNull(key), Objects.requireNonNull(value));
    }

    @SafeVarargs
    static <K, V> Map<K, V> mapEntries(Map.Entry<? extends K, ? extends V>... entries) {
        Map<K, V> out = new LinkedHashMap<K, V>();
        for (Map.Entry<? extends K, ? extends V> entry : entries) {
            K key = Objects.requireNonNull(entry.getKey());
            V value = Objects.requireNonNull(entry.getValue());
            if (out.containsKey(key)) throw new IllegalArgumentException("duplicate key");
            out.put(key, value);
        }
        return Collections.unmodifiableMap(out);
    }

    static <K, V> Map<K, V> mapCopy(Map<K, V> source) {
        Map<K, V> out = new LinkedHashMap<K, V>();
        for (Map.Entry<K, V> entry : source.entrySet()) out.put(Objects.requireNonNull(entry.getKey()), Objects.requireNonNull(entry.getValue()));
        return Collections.unmodifiableMap(out);
    }
}
