package dev.rowstile;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.StringJoiner;

/** A row's key as Postgres writes it: what a message shows, and what the {@code authz.*} functions read back. */
final class Keys {
    private Keys() {}

    /**
     * {@code 7}, or {@code (1,2)} for a key of several columns, given as any array ({@code Object[]}, {@code long[]};
     * Kotlin's {@code arrayOf(1, 2)}) or {@link Collection} of its values, in the key's order: a field is quoted only
     * where Postgres would, when it is empty or holds a comma, a quote, a backslash, a parenthesis or one of ASCII's
     * six spaces, and for no other character. {@code null} for no key.
     */
    static String text(Object key) {
        List<?> values = columns(key);
        if (values == null) {
            return key == null ? null : key.toString();
        }
        if (values.size() == 1) {
            return text(values.get(0));
        }
        StringJoiner row = new StringJoiner(",", "(", ")");
        for (Object v : values) {
            row.add(field(v));
        }
        return row.toString();
    }

    /** The columns of a key of several (an array or a collection), or null for a key of one value. */
    private static List<?> columns(Object key) {
        if (key instanceof Collection<?> values) {
            return new ArrayList<>(values);
        }
        if (key == null || !key.getClass().isArray()) {
            return null;
        }
        List<Object> values = new ArrayList<>();
        for (int i = 0; i < Array.getLength(key); i++) {
            values.add(Array.get(key, i));
        }
        return values;
    }

    private static String field(Object value) {
        if (value == null) {
            return "";
        }
        String text = value.toString();
        boolean quoted = text.isEmpty();
        for (int i = 0; i < text.length() && !quoted; i++) {
            quoted = "\",\\() \t\n\r\u000b\f".indexOf(text.charAt(i)) >= 0;
        }
        return quoted ? '"' + text.replace("\\", "\\\\").replace("\"", "\"\"") + '"' : text;
    }
}
