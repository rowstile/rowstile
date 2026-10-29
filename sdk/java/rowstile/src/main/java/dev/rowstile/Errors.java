package dev.rowstile;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.postgresql.util.PSQLException;
import org.postgresql.util.ServerErrorMessage;

/**
 * Database errors read as rowstile's answers. Each error the runtime raises names its code in the HINT ({@code
 * rowstile help AZ709}), which says what it means and the HTTP status to answer it with. These read any exception
 * that holds Postgres's (its cause, or a cause of that: Spring's, Hibernate's, {@link DatabaseError}).
 */
public final class Errors {
    private Errors() {}

    private static final Pattern CODE = Pattern.compile("rowstile help (AZ\\d{3})");
    // Postgres's own words, not rowstile's: a check of a row no rule's own refusal covers. Postgres names the table
    // without its schema, and sets no field for it
    private static final Pattern GENERIC = Pattern.compile(
            "(new|target) row violates row-level security policy (\\(USING expression\\) )?for table \"([^\"]+)\"");
    private static final String UNSEEN = "this user may not see the row as written (the select rule). An insert that"
            + " reads it back (RETURNING), an upsert, and an update with a WHERE need to see it.";

    // rowstile's codes for a call the database turned down that is no refusal, and what their pages say to answer
    // (rowstile help AZ703: a login refused; AZ708: what the call names isn't there; AZ710: a missing or wrong
    // argument; AZ713: moved inside itself; AZ714: sign in first)
    private record Call(String type, String title, int status) {}

    private static final Map<String, Call> CALLS = Map.of(
            "AZ703", new Call("not-signed-in", "Unauthorized", 401),
            "AZ708", new Call("not-found", "Not Found", 404),
            "AZ710", new Call("bad-argument", "Bad Request", 400),
            "AZ713", new Call("conflict", "Conflict", 409),
            "AZ714", new Call("not-signed-in", "Unauthorized", 401));

    /** Postgres's error in {@code e}: the first PSQLException among it and its causes. */
    private static Optional<PSQLException> postgres(Throwable e) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable t = e; t != null && seen.add(t); t = t.getCause()) {
            if (t instanceof PSQLException p) {
                return Optional.of(p);
            }
        }
        return Optional.empty();
    }

    /** The server's fields of Postgres's error in {@code e}; none for an error the driver raised itself. */
    private static Optional<ServerErrorMessage> server(Throwable e) {
        return postgres(e).map(PSQLException::getServerErrorMessage);
    }

    /** The SQLSTATE of Postgres's error in {@code e}. */
    public static Optional<String> sqlState(Throwable e) {
        return postgres(e).map(PSQLException::getSQLState);
    }

    /**
     * rowstile's code for a database error ({@code AZ709}; {@code rowstile help AZ709} says what it means): from its
     * HINT, where the runtime puts it, or its message. None for an error rowstile didn't raise.
     */
    public static Optional<String> errorCode(Throwable e) {
        Optional<ServerErrorMessage> m = server(e);
        for (String text : m.isPresent() ? List.of(text(m.get().getHint()), text(m.get().getMessage())) : List.<String>of()) {
            Matcher found = CODE.matcher(text);
            if (found.find()) {
                return Optional.of(found.group(1));
            }
        }
        return Optional.empty();
    }

    private static String text(String s) {
        return s == null ? "" : s;
    }

    /**
     * Whether {@code e} is the not-signed-in error ({@code rowstile help AZ701}): a query that needs to know who is
     * asking ran in a transaction nobody signed in to, a bug in the app. A login refused (AZ703) and settings changed
     * by hand (AZ702) share its SQLSTATE, 28000, but are no such thing.
     */
    public static boolean notSignedIn(Throwable e) {
        return sqlState(e).filter("28000"::equals).isPresent() && errorCode(e).orElse("AZ701").equals("AZ701");
    }

    /**
     * A {@link Refused} for an error that is the database refusing a write (SQLSTATE 42501, raised by rowstile's
     * policies with the rule and why, or Postgres's own words for a row no rule's refusal covers). Another 42501 (a
     * table the app role was never granted) is the app's mistake, not a refusal: none.
     */
    public static Optional<Refused> refusal(Throwable e) {
        Optional<ServerErrorMessage> found = server(e).filter(m -> "42501".equals(m.getSQLState()));
        if (found.isEmpty()) {
            return Optional.empty();
        }
        ServerErrorMessage m = found.get();
        String message = text(m.getMessage());
        String code = errorCode(e).orElse(null);
        Matcher generic = GENERIC.matcher(message);
        boolean postgresOwn = generic.lookingAt();
        if (!postgresOwn && (code == null || CALLS.containsKey(code))) {
            return Optional.empty(); // sign in first (AZ714) is a 42501 too, but no refusal: a 401
        }
        Throwable cause = postgres(e).orElseThrow();
        if (postgresOwn) {
            String table = generic.group(3);
            if (generic.group(1).equals("target")) {
                // MERGE matched a row the update or the delete rule hides; Postgres doesn't say which
                return Optional.of(new Refused(message
                        + ": MERGE matched a row the update or delete rule doesn't let this user change",
                        table, null, List.of(), null, cause));
            }
            if (generic.group(2) != null) {
                // an upsert (INSERT ... ON CONFLICT DO UPDATE) whose existing row this user may not update, or see
                return Optional.of(new Refused(message + ": the row is there already, and the update rule (or the"
                        + " select rule) doesn't let this user change it (ON CONFLICT DO UPDATE)",
                        table, "update", List.of(), null, cause));
            }
            // the select rule, on the row as written: an insert that reads it back (RETURNING, or an ORM that reads
            // the new row), an upsert, or an update after which the row would be out of this user's sight
            return Optional.of(new Refused(message + ": " + UNSEEN, table, "select", List.of(), null, cause));
        }
        String detail = m.getDetail();
        String constraint = text(m.getConstraint());
        // Postgres names the schema of every table it names
        String table = m.getTable() == null ? null : m.getSchema() + "." + m.getTable();
        return Optional.of(new Refused(
                message,
                table,
                constraint.startsWith("authz_") ? constraint.substring(6) : null,
                detail == null ? List.of() : List.of(detail.split("\n", -1)),
                code,
                cause));
    }

    /**
     * The problem body and status for {@code e}, if it is one of rowstile's answers: a refusal (403, with the rule and
     * the reason, or the database's own code: AZ704, AZ705, AZ715), a row that isn't there (404), or a call the
     * database turned down that is no refusal, as its code's page says, with the database's words: a login refused or
     * a call that needs someone signed in 401 (AZ703, AZ714), something it names that isn't there 404 (AZ708), an
     * argument missing or wrong 400 (AZ710), a move inside itself 409 (AZ713). None for anything else: the app's
     * mistakes (a share the policy doesn't declare, AZ706; a name not in the policy, AZ707; who is signed in changed
     * by hand, AZ702; nobody signed in, AZ701) stay errors, a 500.
     */
    public static Optional<Problem> problem(Throwable e) {
        if (e instanceof Refused r) {
            return Optional.of(r.problem());
        }
        if (e instanceof NotFound n) {
            return Optional.of(n.problem());
        }
        Optional<Refused> refused = refusal(e);
        if (refused.isPresent()) {
            return Optional.of(refused.get().problem());
        }
        return errorCode(e).filter(CALLS::containsKey).map(code -> {
            Call call = CALLS.get(code);
            String detail = text(server(e).orElseThrow().getMessage());
            return new Problem(Problem.PAGES + call.type(), call.title(), call.status(), detail, Map.of("code", code));
        });
    }
}
