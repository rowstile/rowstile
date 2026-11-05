package dev.rowstile;

import java.io.Serial;
import java.util.Map;

/** The row isn't there, or whoever the transaction acts for can't see it. A 404. */
public final class NotFound extends RuntimeException {
    @Serial
    private static final long serialVersionUID = 1L;

    private final String table;
    private final String id;

    /**
     * {@code app.notes 7 not found}; {@code app.notes not found} without a key, {@code row 7 not found} without a
     * table, or {@code not found}, as every SDK words it. The key is written as the database writes it: {@code 7}, or
     * {@code (1,2)} for a key of several columns (an array or a {@link java.util.Collection} of its values).
     */
    public NotFound(String table, Object key) {
        super(said(table, Keys.text(key)));
        this.table = table;
        this.id = Keys.text(key);
    }

    private static String said(String table, String id) {
        if (id == null) {
            return table == null ? "not found" : table + " not found";
        }
        return (table == null ? "row" : table) + " " + id + " not found";
    }

    /** The table, with its schema. */
    public String table() {
        return table;
    }

    /** The row's key, as the database writes it. */
    public String id() {
        return id;
    }

    /** The problem body for a 404. */
    public Problem problem() {
        return new Problem(Problem.PAGES + "not-found", "Not Found", 404, getMessage(), Map.of());
    }
}
