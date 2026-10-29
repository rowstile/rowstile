package dev.rowstile.conformance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.rowstile.Authz;
import dev.rowstile.ConnectionProblem;
import dev.rowstile.DatabaseError;
import dev.rowstile.Errors;
import dev.rowstile.NotFound;
import dev.rowstile.ObjectType;
import dev.rowstile.Permission;
import dev.rowstile.Principal;
import dev.rowstile.Problem;
import dev.rowstile.Refused;
import dev.rowstile.Rowstile;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** The SDK's own calls over JDBC, and how it reads the database's answers. */
class SdkTest extends Conformance {
    @BeforeEach
    void rows() throws SQLException {
        seed();
    }

    static <T> T as(long user, Rowstile.SqlWork<T> work) throws SQLException {
        try (Connection conn = DriverManager.getConnection(WORKER.appUrl())) {
            return Rowstile.transaction(conn, Principal.user(user), work);
        }
    }

    static long count(Connection c, String sql) throws SQLException {
        try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            rs.next();
            return rs.getLong(1);
        }
    }

    @Test
    @DisplayName("a key is spelled as the database writes it: 7, (1,2), a field quoted only where Postgres would")
    void keys() {
        List<Object> keys = List.of(7, List.of(7), List.of(1, 2), List.of("a b", "x,y"), List.of("", "q\"t"),
                List.of("b\\s", "(1)"), Arrays.asList(1, null));
        List<String> shown = keys.stream().map(k -> new NotFound("app.members", k).id()).toList();
        assertEquals(List.of("7", "7", "(1,2)", "(\"a b\",\"x,y\")", "(\"\",\"q\"\"t\")", "(\"b\\\\s\",\"(1)\")", "(1,)"),
                shown);
        NotFound gone = new NotFound("app.members", List.of(1, 2));
        assertEquals("app.members (1,2) not found", gone.getMessage());
        assertEquals("app.members", gone.table());
        Problem p = gone.problem();
        assertEquals(List.of("https://rowstile.dev/problems/not-found", "Not Found", "app.members (1,2) not found"),
                List.of(p.type(), p.title(), p.detail()));
        assertEquals(404, p.status());
        assertEquals(Map.of(), p.members());
    }

    @Test
    @DisplayName("Postgres's own refusals, where no rule's refusal speaks first, are read for what refused")
    void postgresOwn() throws SQLException {
        // cy (3): author of note 4 in project 1, a member there
        List<String> statements = List.of(
                "UPDATE app.notes SET project_id = 2 WHERE id = 4", // into bo's project: the select rule's
                "INSERT INTO app.notes (id, project_id, author_id, body) VALUES (1, 1, 3, 'x') ON CONFLICT (id) DO"
                        + " UPDATE SET body = 'x'", // note 1 is ann's: the update rule's
                "MERGE INTO app.notes n USING (VALUES (1)) s(id) ON n.id = s.id WHEN MATCHED THEN UPDATE SET body = 'x'");
        List<Refused> refused = statements.stream().map(sql -> {
            DatabaseError e = assertThrows(DatabaseError.class, () -> as(3, c -> {
                try (Statement st = c.createStatement()) {
                    return st.executeUpdate(sql);
                }
            }));
            return Errors.refusal(e).orElseThrow();
        }).toList();
        assertEquals(Arrays.asList("notes", "select", List.of(), "notes", "update", List.of(), "notes", null, List.of()),
                refused.stream().flatMap(r -> Arrays.asList(r.table(), r.command(), r.why()).stream()).toList());
        assertEquals("new row violates row-level security policy for table \"notes\": this user may not see the row"
                + " as written (the select rule). An insert that reads it back (RETURNING), an upsert, and an update"
                + " with a WHERE need to see it.", refused.get(0).getMessage());
        assertEquals("new row violates row-level security policy (USING expression) for table \"notes\": the row is"
                + " there already, and the update rule (or the select rule) doesn't let this user change it (ON"
                + " CONFLICT DO UPDATE)", refused.get(1).getMessage());
        assertEquals("target row violates row-level security policy (USING expression) for table \"notes\": MERGE"
                + " matched a row the update or delete rule doesn't let this user change", refused.get(2).getMessage());
        assertEquals("AZ709", refused.get(2).code());
    }

    @Test
    @DisplayName("refused means the database said no: a 42501 that isn't a policy's is the app's mistake")
    void notARefusal() throws SQLException {
        // a table the app role was never granted
        DatabaseError denied = assertThrows(DatabaseError.class, () -> as(1, c -> count(c,
                "SELECT count(*) FROM public.flyway_schema_history")));
        assertEquals(Optional.of("42501"), Errors.sqlState(denied));
        assertEquals(Optional.empty(), Errors.refusal(denied));
        assertEquals(Optional.empty(), Errors.problem(denied));
        assertFalse(Errors.notSignedIn(denied));
        // no database's error at all, the driver's own, and a chain of causes that goes round
        RuntimeException plain = new RuntimeException("no");
        SQLException refusedConnection = assertThrows(SQLException.class,
                () -> DriverManager.getConnection("jdbc:postgresql://localhost:1/x?connectTimeout=1").close());
        Exception a = new Exception("a");
        Exception b = new Exception("b", a);
        a.initCause(b);
        for (Throwable e : List.of(plain, refusedConnection, a)) {
            assertEquals(Optional.empty(), Errors.problem(e), e.toString());
            assertEquals(Optional.empty(), Errors.errorCode(e), e.toString());
        }
        assertEquals(Optional.empty(), Errors.sqlState(plain));
        assertTrue(Errors.sqlState(refusedConnection).isPresent());
        assertFalse(Errors.notSignedIn(plain));
        // a login refused has the not-signed-in error's SQLSTATE, but is no such thing
        DatabaseError login = assertThrows(DatabaseError.class, () -> as(1, c -> count(c,
                "SELECT count(*) FROM authz.login_key('ak_nope')")));
        assertEquals(List.of(Optional.of("28000"), Optional.of("AZ703")),
                List.of(Errors.sqlState(login), Errors.errorCode(login)));
        assertFalse(Errors.notSignedIn(login));
    }

    @Test
    @DisplayName("a transaction signs in, commits what its work did, and rolls back what fails")
    void transactions() throws SQLException {
        try (Connection conn = DriverManager.getConnection(WORKER.appUrl())) {
            assertEquals(List.of(2L, 3L, 4L), Rowstile.transaction(conn, Principal.user(3), c -> {
                try (Statement st = c.createStatement()) {
                    st.executeUpdate("UPDATE app.notes SET body = 'better idea' WHERE id = 4");
                }
                return List.of(count(c, "SELECT count(*) FROM app.projects"), count(c, "SELECT count(*) FROM app.notes"),
                        count(c, "SELECT max(id) FROM app.notes WHERE body = 'better idea'"));
            }));
            // what fails is rolled back: the update, then a refusal
            Refused refused = assertThrows(Refused.class, () -> Rowstile.transaction(conn, Principal.user(3), c -> {
                try (Statement st = c.createStatement()) {
                    st.executeUpdate("UPDATE app.notes SET body = 'gone' WHERE id = 4");
                    return Authz.on(c).expect(st.executeUpdate("UPDATE app.notes SET body = 'x' WHERE id = 1"),
                            "app.notes", "update", 1);
                }
            }));
            assertEquals("permission denied: user 3 may not update row 1 of app.notes", refused.getMessage());
            assertEquals(0L, (long) Rowstile.transaction(conn, Principal.user(3),
                    c -> count(c, "SELECT count(*) FROM app.notes WHERE body = 'gone'")));
            assertTrue(conn.getAutoCommit());
            // a transaction open already: this one's sign-in would end with it, so it says how instead
            conn.setAutoCommit(false);
            IllegalStateException open = assertThrows(IllegalStateException.class,
                    () -> Rowstile.transaction(conn, Principal.user(3), c -> 1));
            assertTrue(open.getMessage().contains("Rowstile.signIn(conn, who)"), open.getMessage());
            Rowstile.signIn(conn, Principal.NOBODY);
            assertEquals(1L, count(conn, "SELECT count(*) FROM app.projects")); // the public one
            conn.rollback();
        }
    }

    @Test
    @DisplayName("the calls take the policy's names, or any name without the generated ones")
    void calls() throws SQLException {
        assertEquals(List.of(true, false), as(2, c -> List.of(Authz.on(c).can(Permission.of("note", "edit"), 2),
                Authz.on(c).can(Permission.of("note", "edit"), 3))));
        List<Permission> perms = as(2, c -> Authz.on(c).perms(ObjectType.of("note"), 2));
        assertEquals(List.of(Permission.of("note", "edit"), Permission.of("note", "view")), perms);
        assertEquals(List.of("edit", "view"), perms.stream().map(Permission::permission).toList());
        assertEquals("note", ObjectType.of("note").name());
        assertEquals(Map.of("2", List.of(AuthzNames.ProjectPermission.EDIT, AuthzNames.ProjectPermission.VIEW), "3",
                List.of(AuthzNames.ProjectPermission.VIEW)),
                as(2, c -> Authz.on(c).permsOf(AuthzNames.PROJECT, List.of(2L, 3L))));
        assertEquals(List.of("2", "3"), as(2, c -> Authz.on(c).list(AuthzNames.ProjectPermission.VIEW)));
        // an update that matched nothing for another reason than access isn't a refusal: 404
        NotFound other = assertThrows(NotFound.class, () -> as(3, c -> {
            try (Statement st = c.createStatement()) {
                return Authz.on(c).expect(st.executeUpdate(
                        "UPDATE app.notes SET body = 'x' WHERE id = 4 AND body = 'something else'"), "app.notes",
                        "update", 4);
            }
        }));
        assertEquals("app.notes 4 not found", other.getMessage());
        Authz.Verdict allowed = as(3, c -> Authz.on(c).verdict("app.notes", "update", 4));
        assertTrue(allowed.allowed());
        assertEquals("user 3", allowed.who());
        assertEquals(1, (int) as(3, c -> {
            try (Statement st = c.createStatement()) {
                return Authz.on(c).expect(st.executeUpdate("UPDATE app.notes SET body = 'y' WHERE id = 4"),
                        "app.notes", "update", 4);
            }
        }));
        // a table named without its schema is found on the search_path, and named as the policy names it
        Refused bare = assertThrows(Refused.class, () -> as(3, c -> {
            try (Statement st = c.createStatement()) {
                st.execute("SET LOCAL search_path = app");
                return Authz.on(c).expect(st.executeUpdate("UPDATE notes SET body = 'x' WHERE id = 1"), "notes",
                        "update", 1);
            }
        }));
        assertEquals(List.of("app.notes", "update", "AZ709"), List.of(bare.table(), bare.command(), bare.code()));
        assertEquals("app.notes", bare.problem().members().get("table"));
    }

    @Test
    @DisplayName("the connection check says what is wrong with a connection that skips row-level security")
    void connectionCheck() throws SQLException {
        try (Connection owner = owner()) {
            List<Authz.Finding> found = Authz.on(owner).connectionCheck();
            assertTrue(found.stream().anyMatch(f -> f.severity().equals("error")), found.toString());
            ConnectionProblem e = assertThrows(ConnectionProblem.class, () -> Authz.on(owner).check());
            assertTrue(e.problems().stream().anyMatch(p -> p.contains("an owner skips row-level security")),
                    e.problems().toString());
        }
        try (Connection app = DriverManager.getConnection(WORKER.appUrl())) {
            Authz.on(app).check();
            assertEquals(List.of(), Authz.on(app).connectionCheck().stream().filter(f -> f.severity().equals("error"))
                    .toList());
        }
    }
}
