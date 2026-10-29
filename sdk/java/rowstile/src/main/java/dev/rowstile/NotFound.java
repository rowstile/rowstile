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
     * {@code app.notes 7 not found}. The key is written as the database writes it: {@code 7}, or {@code (1,2)} for a
     * key of several columns (a {@link java.util.List} of its values).
     */
    public NotFound(String table, Object key) {
        super(table + " " + Keys.text(key) + " not found");
        this.table = table;
        this.id = Keys.text(key);
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
