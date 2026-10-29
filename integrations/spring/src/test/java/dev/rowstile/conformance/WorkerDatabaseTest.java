package dev.rowstile.conformance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.rowstile.DatabaseError;
import dev.rowstile.Principal;
import dev.rowstile.Rowstile;
import dev.rowstile.testing.WorkerDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Check 12: each test JVM has a database of its own, copied from the migrated one, with the policy. */
class WorkerDatabaseTest {
    static final String TESTS = Conformance.TESTS;

    static String url(String name) {
        return TESTS.replaceFirst("/conf_tests\\?", "/" + name + "?");
    }

    static long users(String url) throws SQLException {
        try (Connection conn = DriverManager.getConnection(url); Statement st = conn.createStatement();
                ResultSet rs = st.executeQuery("SELECT count(*) FROM app.users")) {
            rs.next();
            return rs.getLong(1);
        }
    }

    static void sql(String url, String statement) throws SQLException {
        try (Connection conn = DriverManager.getConnection(url); Statement st = conn.createStatement()) {
            st.execute(statement);
        }
    }

    static List<Long> projects(String appUrl, long who) throws SQLException {
        try (Connection conn = DriverManager.getConnection(appUrl)) {
            return Rowstile.transaction(conn, Principal.user(who), c -> {
                List<Long> ids = new ArrayList<>();
                try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery("SELECT id FROM app.projects ORDER BY id")) {
                    while (rs.next()) {
                        ids.add(rs.getLong(1));
                    }
                }
                return ids;
            });
        }
    }

    @Test
    @DisplayName("12: the framework's test database has the policy: a copy of the migrated one for each test JVM")
    void perWorker() throws SQLException {
        // this JVM's (Surefire's fork number: two JVMs, two copies)
        String worker = System.getProperty("rowstile.worker");
        assertTrue(worker.matches("[12]"), worker);
        assertEquals(worker, WorkerDatabase.workerId());
        assertTrue(Conformance.WORKER.url().contains("/conf_tests_w" + worker + "?"), Conformance.WORKER.url());
        assertTrue(Conformance.WORKER.appUrl().contains("/conf_tests_w" + worker + "?user=conf_app"),
                Conformance.WORKER.appUrl());
        // another worker's, to copy again and again here: what this JVM's tests use stays as it is
        String own = "9" + worker;
        System.setProperty("rowstile.worker", own);
        try {
            WorkerDatabase copy = WorkerDatabase.copy(TESTS, null, null, Conformance.APP, true);
            assertTrue(copy.url().endsWith("/conf_tests_w" + own + "?user=conf_owner&password=owner"), copy.url());
            sql(copy.url(), "INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo')");
            sql(copy.url(), "INSERT INTO app.projects VALUES (1, 1, 'Plans', false)");
            assertEquals(List.of(1L), projects(copy.appUrl(), 1)); // the app's role, under row-level security
            assertEquals(List.of(), projects(copy.appUrl(), 2));
            assertEquals(copy, WorkerDatabase.copy(TESTS, null, null, Conformance.APP, false)); // kept, with what was written
            assertEquals(2, users(copy.url()));
            assertEquals(copy.url(), WorkerDatabase.copy(TESTS, null, null, null, true).url()); // copied again: as migrated
            assertEquals(0, users(copy.url())); // (the original is left as it was migrated)
            assertNull(WorkerDatabase.copy(TESTS, null, null, null, false).appUrl());
            sql(url("postgres"), "DROP DATABASE conf_tests_w" + own + " WITH (FORCE)");
            // a copy that isn't there yet is made, fresh or not
            assertEquals(copy.url(), WorkerDatabase.copy(TESTS, null, null, null, false).url());
            assertEquals(0, users(copy.url()));
            sql(url("postgres"), "DROP DATABASE conf_tests_w" + own + " WITH (FORCE)");
        } finally {
            System.setProperty("rowstile.worker", worker);
        }
    }

    @Test
    @DisplayName("12: ... and a copy that can't be made says why")
    void cantCopy() throws SQLException {
        String worker = System.getProperty("rowstile.worker");
        for (String url : List.of("jdbc:postgresql://localhost", "jdbc:postgresql://localhost/?user=x",
                "jdbc:mysql://localhost/conf_tests")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> WorkerDatabase.copy(url, null, null, null, true));
            assertTrue(e.getMessage().contains("needs a database to copy"), e.getMessage());
        }
        IllegalArgumentException app = assertThrows(IllegalArgumentException.class,
                () -> WorkerDatabase.copy(TESTS, null, null, "postgresql://app", false));
        assertTrue(app.getMessage().contains("not a Postgres JDBC URL"), app.getMessage());
        // the original isn't there: the database's words
        DatabaseError none = assertThrows(DatabaseError.class,
                () -> WorkerDatabase.copy(url("conf_nothing"), null, null, null, true));
        assertEquals("3D000", none.getCause().getSQLState());
        // something connected to the original (a private one, as the other JVM copies conf_tests): Postgres waits
        // five seconds for it to leave, then the copy says what to do
        String held = "conf_held_w" + worker;
        sql(url("postgres"), "DROP DATABASE IF EXISTS " + held + " WITH (FORCE)");
        sql(url("postgres"), "CREATE DATABASE " + held + " TEMPLATE conf_tests");
        try (Connection holding = DriverManager.getConnection(url(held))) {
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> WorkerDatabase.copy(url(held), null, null, null, true));
            assertTrue(e.getMessage().contains("can't be copied while anything is connected to it"), e.getMessage());
            assertTrue(holding.isValid(1));
        } finally {
            sql(url("postgres"), "DROP DATABASE IF EXISTS " + held + "_w" + worker + " WITH (FORCE)");
            sql(url("postgres"), "DROP DATABASE " + held + " WITH (FORCE)");
        }
    }
}
