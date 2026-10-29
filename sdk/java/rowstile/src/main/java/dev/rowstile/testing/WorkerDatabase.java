package dev.rowstile.testing;

import dev.rowstile.DatabaseError;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A test worker's own database, copied from the migrated test database (with the policy), so that tests that write
 * don't meet each other: one for each JVM a test run forks (Maven Surefire's {@code forkCount}, Gradle's
 * {@code maxParallelForks}).
 *
 * <pre>{@code
 * WorkerDatabase db = WorkerDatabase.copy("jdbc:postgresql://localhost/app_tests", "owner", password, appUrl, true);
 * }</pre>
 *
 * @param url the copy's JDBC URL, as the original's with its database's name
 * @param appUrl the app role's URL for the copy, if one was given
 */
public record WorkerDatabase(String url, String appUrl) {
    private static final Pattern URL = Pattern.compile("(jdbc:postgresql://[^/?]*/)([^?]*)(.*)");

    /**
     * This worker's number: the system property {@code rowstile.worker} (Surefire's fork: {@code
     * -Drowstile.worker=${surefire.forkNumber}} in its {@code argLine}), else Gradle's {@code org.gradle.test.worker};
     * {@code 0} in a run that sets neither.
     */
    public static String workerId() {
        return System.getProperty("rowstile.worker", System.getProperty("org.gradle.test.worker", "0"));
    }

    /**
     * A database for this worker, {@code <name>_w<worker>}, copied from {@code url}'s (migrated, with the policy) by a
     * role that may create databases (the owner, {@code user}), while nothing else is connected to the original. A
     * copy an earlier run left is made again, unless {@code fresh} is false. {@code appUrl}: the app role's URL,
     * returned for the copy.
     */
    public static WorkerDatabase copy(String url, String user, String password, String appUrl, boolean fresh) {
        Matcher parts = URL.matcher(url);
        if (!parts.matches() || parts.group(2).isEmpty()) {
            throw new IllegalArgumentException("WorkerDatabase needs a database to copy, and this URL names none: " + url);
        }
        String template = parts.group(2);
        String name = template + "_w" + workerId();
        // CREATE DATABASE ... TEMPLATE needs no one connected to the original, this connection included
        try (Connection conn = DriverManager.getConnection(parts.group(1) + "postgres" + parts.group(3), user, password);
                Statement st = conn.createStatement()) {
            boolean exists;
            try (PreparedStatement q = conn.prepareStatement("SELECT 1 FROM pg_database WHERE datname = ?")) {
                q.setString(1, name);
                exists = q.executeQuery().next();
            }
            if (exists && fresh) {
                st.execute("DROP DATABASE " + quoted(name) + " WITH (FORCE)");
            }
            if (fresh || !exists) {
                create(st, name, template);
            }
        } catch (SQLException e) {
            throw new DatabaseError(e);
        }
        return new WorkerDatabase(named(url, name), appUrl == null ? null : named(appUrl, name));
    }

    private static void create(Statement st, String name, String template) throws SQLException {
        try {
            st.execute("CREATE DATABASE " + quoted(name) + " TEMPLATE " + quoted(template));
        } catch (SQLException e) {
            // 55006: something is connected to the original (Postgres has waited five seconds for it to leave)
            if (!"55006".equals(e.getSQLState())) {
                throw e;
            }
            throw new IllegalStateException("WorkerDatabase: " + template + " can't be copied while anything is"
                    + " connected to it: close what holds it (the app, a migration tool, a console). Where the service"
                    + " keeps a connection of its own for minutes after yours (Neon does), a copy per worker can't be"
                    + " made: use one test database, where each test rolls back, or a branch for each run", e);
        }
    }

    private static String quoted(String name) {
        return '"' + name.replace("\"", "\"\"") + '"';
    }

    private static String named(String url, String name) {
        Matcher parts = URL.matcher(url);
        if (!parts.matches()) {
            throw new IllegalArgumentException("not a Postgres JDBC URL: " + url);
        }
        return parts.group(1) + name + parts.group(3);
    }
}
