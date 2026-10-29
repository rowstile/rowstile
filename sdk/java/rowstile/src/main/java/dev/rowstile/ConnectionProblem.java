package dev.rowstile;

import java.io.Serial;
import java.util.List;

/**
 * {@code authz.connection_check()} found that the app's connection skips row-level security (a superuser, BYPASSRLS,
 * the tables' owner), where the database would filter nothing. The app must not start on it.
 */
public final class ConnectionProblem extends RuntimeException {
    @Serial
    private static final long serialVersionUID = 1L;

    private final String[] problems; // (an array: what an exception holds is serializable)

    public ConnectionProblem(List<String> problems) {
        super("the app's database connection can't be used with rowstile: " + String.join("; ", problems));
        this.problems = problems.toArray(String[]::new);
    }

    /** Each problem, in the database's words. */
    public List<String> problems() {
        return List.of(problems);
    }
}
