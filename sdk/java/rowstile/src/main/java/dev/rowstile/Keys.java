package dev.rowstile;

import java.util.List;
import java.util.StringJoiner;

/** A row's key as Postgres writes it: what a message shows, and what the {@code authz.*} functions read back. */
final class Keys {
    private Keys() {}

    /**
     * {@code 7}, or {@code (1,2)} for a key of several columns (a {@link List} of its values): a field is quoted only
     * where Postgres would, when it is empty or holds a comma, a quote, a backslash, a parenthesis or a space.
     * {@code null} for no key.
     */
    static String text(Object key) {
        if (key instanceof List<?> values) {
            if (values.size() == 1) {
                return text(values.get(0));
            }
            StringJoiner row = new StringJoiner(",", "(", ")");
            for (Object v : values) {
                row.add(field(v));
            }
            return row.toString();
        }
        return key == null ? null : key.toString();
    }

    private static String field(Object value) {
        if (value == null) {
            return "";
        }
        String text = value.toString();
        boolean quoted = text.isEmpty();
        for (int i = 0; i < text.length() && !quoted; i++) {
            char c = text.charAt(i);
            quoted = "\",\\()".indexOf(c) >= 0 || Character.isWhitespace(c);
        }
        return quoted ? '"' + text.replace("\\", "\\\\").replace("\"", "\"\"") + '"' : text;
    }
}
