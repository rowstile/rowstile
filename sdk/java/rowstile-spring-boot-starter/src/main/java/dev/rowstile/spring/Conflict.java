package dev.rowstile.spring;

import dev.rowstile.Problem;
import java.io.Serial;
import java.util.Map;
import org.springframework.dao.OptimisticLockingFailureException;

/**
 * An update or a delete of an entity that matched no row, though the rules allow it: the row changed since it was
 * read (a version column), or the statement asked for more than its key. A 409.
 */
public final class Conflict extends OptimisticLockingFailureException {
    @Serial
    private static final long serialVersionUID = 1L;

    Conflict(Throwable cause) {
        super("the row changed since it was read, and the rules allow the change: read it again", cause);
    }

    /** The problem body for a 409. */
    public Problem problem() {
        return new Problem("https://rowstile.dev/problems/conflict", "Conflict", 409, getMessage(), Map.of());
    }
}
