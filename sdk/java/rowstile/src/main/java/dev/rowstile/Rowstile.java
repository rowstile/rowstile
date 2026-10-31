package dev.rowstile;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * rowstile for Java apps (preview). Every transaction signs in as whoever the request (or the job) acts for, with
 * {@code authz.act_as()}; the database's refusals become {@link Refused} (a 403 with the reason), rows the user can't
 * see become {@link NotFound} (a 404). The SDK holds no rowstile logic: it calls the {@code authz.*} functions the
 * policy made, and translates their answers.
 *
 * <pre>{@code
 * Rowstile.transaction(conn, Principal.user(42), c -> ...);   // BEGIN; SELECT authz.act_as('user', '42'); ...; COMMIT
 * Rowstile.actingAs(Principal.of("service", 3), () -> ...);   // what begins in here signs in as service 3
 * }</pre>
 *
 * <p>The sign-in lasts one transaction, so a pooled connection never carries one request's user into another's, and
 * nothing uses a session-level {@code SET}: pools and poolers in transaction mode are safe.
 */
public final class Rowstile {
    private static final ThreadLocal<Principal> CURRENT = new ThreadLocal<>();
    private static final String ACT_AS = "SELECT authz.act_as(?, ?)";

    private Rowstile() {}

    /** Work on a connection, in a transaction this SDK began. */
    @FunctionalInterface
    public interface SqlWork<T> {
        T run(Connection conn) throws SQLException;
    }

    /** Who the code running on this thread acts for (set by {@link #actingAs} or a job), if anyone set it. */
    public static Optional<Principal> current() {
        return Optional.ofNullable(CURRENT.get());
    }

    /** Runs {@code work} acting for {@code who}: every transaction it begins (the Spring starter's) signs in as them. */
    public static <T> T actingAs(Principal who, Supplier<T> work) {
        Principal before = CURRENT.get();
        CURRENT.set(who);
        try {
            return work.get();
        } finally {
            if (before == null) {
                CURRENT.remove();
            } else {
                CURRENT.set(before);
            }
        }
    }

    /**
     * A background job (an executor's task, a {@code @Scheduled} method's body) that acts for {@code who}, whatever
     * started it: {@code executor.submit(Rowstile.job(Principal.of("service", 3), () -> ...))}.
     */
    public static Runnable job(Principal who, Runnable work) {
        return () -> actingAs(who, () -> {
            work.run();
            return null;
        });
    }

    /**
     * Signs the transaction open on {@code conn} in as {@code who} ({@link Principal#NOBODY}: nobody), until it ends:
     * {@code SELECT authz.act_as('user', '42')}. The first statement of a transaction, before any other.
     */
    public static void signIn(Connection conn, Principal who) throws SQLException {
        try (PreparedStatement st = conn.prepareStatement(ACT_AS)) {
            st.setString(1, who.nobody() ? null : who.type());
            st.setString(2, who.id());
            st.execute();
        }
    }

    /**
     * The error for {@code who}'s work inside a transaction signed in as {@code signed}, thrown before anything is
     * sent for it. A sign-in lasts the database transaction, so signing in again inside it would make everything after
     * it {@code who}'s: a transaction is one principal's. The Spring starter and the Kotlin module throw it.
     */
    public static IllegalStateException signedInAlready(Principal signed, Principal who) {
        return new IllegalStateException("this transaction is signed in as " + name(signed) + " already, and a "
                + "sign-in lasts the database transaction: " + name(who) + "'s work can't run inside it. Run it after, "
                + "or in a transaction of its own (another connection)");
    }

    /** {@code user 42}, {@code service 3} or {@code nobody}, as the database's own words name a principal. */
    private static String name(Principal p) {
        return p.nobody() ? "nobody" : p.type() + " " + p.id();
    }

    /**
     * A transaction on {@code conn}, signed in as {@code who}: it commits what {@code work} did, or rolls it back if
     * {@code work} throws. The connection must be in auto-commit mode (no transaction open on it); it is again after.
     * A database error is thrown as {@link DatabaseError}.
     */
    public static <T> T transaction(Connection conn, Principal who, SqlWork<T> work) {
        try {
            if (!conn.getAutoCommit()) {
                throw new IllegalStateException(
                        "a transaction is open on this connection already: sign it in with Rowstile.signIn(conn, who)");
            }
            conn.setAutoCommit(false);
            try {
                signIn(conn, who);
                T result = work.run(conn);
                conn.commit();
                return result;
            } catch (SQLException | RuntimeException e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw new DatabaseError(e);
        }
    }
}
