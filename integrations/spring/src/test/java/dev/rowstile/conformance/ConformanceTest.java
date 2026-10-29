package dev.rowstile.conformance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.rowstile.Errors;
import dev.rowstile.NotFound;
import dev.rowstile.Principal;
import dev.rowstile.Refused;
import dev.rowstile.Rowstile;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.postgresql.util.PSQLException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;

/**
 * The conformance suite (integrations/README.md): the same checks for every stack. This is Spring Boot, Spring MVC
 * and Spring Security, JPA and JdbcClient over HikariCP, Flyway. test.sh does check 11 (a fresh database: migrate,
 * the policy's tests, then Flyway's own validate shows no change) before these run.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"server.error.include-message=always", "spring.web.error.include-message=always"})
class ConformanceTest extends Conformance {
    @LocalServerPort
    int port;

    @Autowired
    Notes notes;

    @Autowired
    PlatformTransactionManager transactions;

    @Autowired
    Digest digest;

    @BeforeEach
    void rows() throws SQLException {
        seed();
    }

    Reply call(String method, String path, String who, Object body) {
        return call(port, method, path, who, body);
    }

    Reply call(String method, String path, String who, Object body, Map<String, String> headers) {
        return call(port, method, path, who, body, headers);
    }

    @Test
    @DisplayName("1: signed in, a list shows only the user's rows")
    void lists() {
        for (String user : List.of("1", "2", "3")) {
            assertEquals(NOTES.get(user), call("GET", "/notes", user, null).ids(), user);
        }
    }

    @Test
    @DisplayName("2: signed out on purpose, only what anyone may see")
    void signedOut() {
        assertEquals(NOTES.get(""), call("GET", "/notes", null, null).ids());
        assertEquals(List.of(3L), call("GET", "/projects", null, null).ids());
    }

    @Test
    @DisplayName("3: not signed in: the not-signed-in error (AZ701), naming act_as")
    void notSignedIn() throws SQLException {
        try (Connection conn = DriverManager.getConnection(WORKER.appUrl()); Statement st = conn.createStatement()) {
            conn.setAutoCommit(false);
            PSQLException e = assertThrows(PSQLException.class, () -> st.executeQuery("SELECT count(*) FROM app.notes"));
            assertEquals("28000", e.getSQLState());
            String hint = e.getServerErrorMessage().getHint();
            assertTrue(hint.contains("act_as"), hint);
            assertEquals("AZ701", Errors.errorCode(e).orElseThrow()); // rowstile help AZ701
            assertTrue(Errors.notSignedIn(e));
        }
    }

    @Test
    @DisplayName("5: concurrent requests never mix users")
    void concurrent() {
        List<String> users = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            users.addAll(List.of("1", "2", "3", ""));
        }
        List<CompletableFuture<Reply>> sent = users.stream()
                .map(u -> send(port, "GET", "/notes", u.isEmpty() ? null : u, null, Map.of()))
                .toList();
        for (int i = 0; i < users.size(); i++) {
            assertEquals(NOTES.get(users.get(i)), sent.get(i).join().ids(), users.get(i));
        }
    }

    @Test
    @DisplayName("6: a refused insert: 403 with the problem body naming the rule")
    void refusedInsert() {
        Reply r = call("POST", "/notes", "2", Map.of("projectId", 3, "body", "hi"));
        assertEquals(403, r.status(), r.text());
        assertEquals("application/problem+json", r.type());
        JsonNode body = r.json();
        assertEquals("app.notes", body.get("table").asString(), r.text());
        assertEquals("insert", body.get("command").asString(), r.text());
        assertEquals("AZ709", body.get("code").asString(), r.text()); // rowstile help AZ709
        assertTrue(body.get("detail").asString().contains("user 2 may not insert this row into app.notes"), r.text());
        assertTrue(body.get("why").valueStream().anyMatch(l -> l.asString().contains("project.edit")), r.text());
    }

    @Test
    @DisplayName("7: an update of a hidden row: 404; of a visible row the user may not edit: 403, with the reason")
    void hiddenAndRefused() {
        Reply hidden = call("PATCH", "/notes/1", "2", Map.of("body", "x"));
        Reply refused = call("PATCH", "/notes/1", "3", Map.of("body", "x"));
        Reply mine = call("PATCH", "/notes/4", "3", Map.of("body", "better idea"));
        Reply gone = call("DELETE", "/notes/2", "1", null);
        Reply no = call("DELETE", "/notes/1", "3", null);
        assertProblem(hidden, "not-found", "Not Found", 404, "app.notes 1 not found", null);
        assertEquals(403, refused.status(), refused.text());
        assertEquals("update", refused.json().get("command").asString(), refused.text());
        assertTrue(refused.json().get("why").valueStream().anyMatch(l -> l.asString().contains("edit")), refused.text());
        // worded as the database words a refused insert: who, the command, the row, the table
        assertEquals("permission denied: user 3 may not update row 1 of app.notes",
                refused.json().get("detail").asString(), refused.text());
        assertEquals(200, mine.status(), mine.text());
        assertProblem(gone, "not-found", "Not Found", 404, "app.notes 2 not found", null);
        assertEquals(403, no.status(), no.text());
        assertEquals("delete", no.json().get("command").asString(), no.text());
        assertEquals("permission denied: user 3 may not delete row 1 of app.notes",
                no.json().get("detail").asString(), no.text());
        assertEquals(List.of(1L, 3L, 4L), call("GET", "/notes", "1", null).ids()); // nothing deleted
    }

    @Test
    @DisplayName("7: ... and a row hidden by the time its update reaches the database is 404")
    void hiddenMeanwhile() throws SQLException {
        TransactionTemplate tx = new TransactionTemplate(transactions);
        NotFound e = assertThrows(NotFound.class, () -> Rowstile.actingAs(Principal.user(1), () -> tx.execute(s -> {
            Note note = notes.findById(4L).orElseThrow(); // cy's note in ann's project, which ann reads
            try {
                sql("UPDATE app.notes SET project_id = 2 WHERE id = 4"); // someone moves it meanwhile, to bo's
            } catch (SQLException x) {
                throw new IllegalStateException(x);
            }
            note.setBody("x");
            return null;
        })));
        assertEquals("app.notes 4 not found", e.getMessage());
        assertEquals("https://rowstile.dev/problems/not-found", e.problem().type());
    }

    @Test
    @DisplayName("7: an entity's delete the rules refuse is refused too, and says why")
    void refusedDelete() {
        TransactionTemplate tx = new TransactionTemplate(transactions);
        Refused e = assertThrows(Refused.class, () -> Rowstile.actingAs(Principal.user(3), () -> tx.execute(s -> {
            notes.delete(notes.findById(1L).orElseThrow());
            return null;
        })));
        assertEquals("permission denied: user 3 may not delete row 1 of app.notes", e.getMessage());
        assertEquals(List.of("delete", "app.notes", "AZ709"), List.of(e.command(), e.table(), e.code()));
        assertTrue(e.why().get(0).startsWith("no"), e.why().toString());
    }

    @Test
    @DisplayName("8: insert, then read back, works when the select rule allows it, and is explained when not")
    void insertReadBack() {
        Reply ok = call("POST", "/notes", "1", Map.of("projectId", 1, "body", "new"));
        Reply unreadable = call("POST", "/inbox", "1", Map.of("recipientId", 2, "body", "hi bo"));
        Reply quiet = call("POST", "/inbox/quietly", "1", Map.of("recipientId", 2, "body", "hi bo"));
        assertEquals(201, ok.status(), ok.text());
        assertTrue(ok.json().get("id").asLong() > 100, ok.text());
        assertEquals(403, unreadable.status(), unreadable.text());
        assertEquals("select", unreadable.json().get("command").asString(), unreadable.text());
        assertTrue(unreadable.json().get("detail").asString().contains("may not see the row as written"),
                unreadable.text());
        assertEquals(202, quiet.status(), quiet.text());
    }

    long key(String name, String scopes) throws SQLException {
        try (Connection conn = owner(); Statement st = conn.createStatement()) { // a key of ann's, made as she
            conn.setAutoCommit(false);
            st.execute("SELECT authz.act_as('user', '1')");
            st.execute("SELECT authz.create_api_key('" + name + "', '" + scopes + "')");
            conn.commit();
            try (ResultSet rs = st.executeQuery("SELECT max(id) FROM authz.api_keys WHERE user_id = '1'")) {
                rs.next();
                return rs.getLong(1);
            }
        }
    }

    @Test
    @DisplayName("16: a call the database turns down that is no refusal: not there (AZ708) 404, a wrong argument (AZ710) 400")
    void notThereAndWrongArgument() throws SQLException {
        long key = key("ci", "");
        Reply page = call("GET", "/projects/page?limit=1", "1", null);
        Reply negative = call("GET", "/projects/page?limit=-1", "1", null);
        Reply cursor = call("GET", "/projects/page?limit=1&after=x", "1", null);
        Reply others = call("DELETE", "/keys/" + key, "2", null); // bo's key it isn't
        Reply revoked = call("DELETE", "/keys/" + key, "1", null);
        Reply again = call("DELETE", "/keys/" + key, "1", null); // revoked: there is none now
        assertEquals("[\"1\"]", page.text());
        assertProblem(negative, "bad-argument", "Bad Request", 400, "the page size must not be negative (got -1)",
                "AZ710");
        assertProblem(cursor, "bad-argument", "Bad Request", 400, "the page cursor 'x' is not a project id", "AZ710");
        assertEquals(204, revoked.status(), revoked.text());
        // no refusal: for this user the key isn't there (bo's own keys don't hold it; ann's no longer do)
        for (Reply r : List.of(others, again)) {
            assertProblem(r, "not-found", "Not Found", 404, "no API key " + key + " of yours", "AZ708");
        }
    }

    @Test
    @DisplayName("16: and the other codes, each as its page says: 401, 409, a refusal 403; the app's mistakes a 500")
    void eachCode() throws SQLException {
        String readOnly;
        try (Connection conn = owner(); Statement st = conn.createStatement()) { // a key of ann's that may only read
            conn.setAutoCommit(false);
            st.execute("SELECT authz.act_as('user', '1')");
            try (ResultSet rs = st.executeQuery("SELECT authz.create_api_key('ro', 'read')")) {
                rs.next();
                readOnly = rs.getString(1);
            }
            conn.commit();
        }
        Reply nobody = call("POST", "/keys", null, Map.of("name", "k"));
        Reply asks = call("POST", "/projects/1/requests", null, Map.of("relation", "member", "reason", "the review"));
        Reply badKey = call("POST", "/keys", "1", Map.of("name", "k"), Map.of("x-api-key", "ak_nope"));
        Reply scoped = call("POST", "/keys", "1", Map.of("name", "k"), Map.of("x-api-key", readOnly));
        Reply made = call("POST", "/keys", "1", Map.of("name", "k"));
        Reply notShared = call("GET", "/projects/1/shares", "2", null);
        Reply inside = call("PATCH", "/folders/1", "1", Map.of("parentId", 2));
        Reply stays = call("PATCH", "/folders/2", "1", Map.of("parentId", 1));
        Reply service = call("POST", "/keys", "service:1", Map.of("name", "mine")); // a key for itself
        assertEquals(201, made.status(), made.text());
        assertTrue(made.json().get("key").asString().startsWith("ak_"), made.text());
        assertEquals(200, stays.status(), stays.text());
        assertProblem(nobody, "not-signed-in", "Unauthorized", 401, "sign in to create an API key", "AZ714");
        assertProblem(asks, "not-signed-in", "Unauthorized", 401, "sign in first", "AZ714");
        assertProblem(badKey, "not-signed-in", "Unauthorized", 401, "invalid API key", "AZ703");
        assertProblem(inside, "conflict", "Conflict", 409, "folder 1 cannot be moved inside itself", "AZ713");
        // refusals, by the database's own code: 403, naming no rule
        for (Object[] each : List.of(new Object[] {scoped, "this session is read-only", "AZ704"},
                new Object[] {notShared, "you cannot see the shares of project 1", "AZ705"})) {
            Reply r = (Reply) each[0];
            assertEquals(403, r.status(), r.text());
            JsonNode got = r.json();
            assertEquals("https://rowstile.dev/problems/refused", got.get("type").asString(), r.text());
            assertEquals(each[2], got.get("code").asString(), r.text());
            assertTrue(got.get("detail").asString().startsWith((String) each[1]), r.text());
            assertTrue(got.get("table").isNull() && got.get("command").isNull(), r.text());
        }
        // a call that is for users, made by a service (rowstile help AZ715): a refusal too, 403
        assertProblem(service, "refused", "Forbidden", 403,
                "authz.create_api_key for oneself is for users, not services (service 1 is signed in)", "AZ715");
        assertEquals(0, service.json().get("why").size(), service.text());
        // the app's mistakes stay errors: a share the policy doesn't declare, a name not in the policy, who is
        // signed in changed by hand
        Map<String, Reply> errors = Map.of(
                "the policy does not allow sharing project.member with a user [AZ706]",
                call("POST", "/projects/1/requests", "2", Map.of("relation", "member", "reason", "the review")),
                "the policy gives service no manage_keys permission, so nobody manages its keys [AZ707]",
                call("POST", "/keys", "1", Map.of("name", "k", "principalType", "service", "principalId", "1")),
                "who is signed in was changed after signing in [AZ702]",
                call("GET", "/notes/as/2", "1", null));
        errors.forEach((words, r) -> {
            assertEquals(500, r.status(), r.text());
            String message = r.json().get("message").asString();
            String said = words.substring(0, words.indexOf(" ["));
            String code = words.substring(words.indexOf('[') + 1, words.length() - 1);
            assertTrue(message.contains(said) && message.contains("rowstile help " + code), message);
        });
    }

    @Test
    @DisplayName("10: a background job signs in as a service principal")
    void job() throws Exception {
        Digest.Seen seen = Rowstile.actingAs(Principal.user(3), digest::run); // whatever started it
        assertEquals(Principal.of("service", 1), seen.who());
        assertEquals(2, seen.projects()); // project 1 (it is added to) and the public one
        // a job handed to an executor acts for its principal on the executor's thread, and nobody after it
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            AtomicReference<Long> counted = new AtomicReference<>();
            pool.submit(Rowstile.job(Principal.of("service", 1), () -> counted.set(digest.run().projects()))).get();
            assertEquals(2L, counted.get());
            assertEquals(Optional.empty(), pool.submit(Rowstile::current).get());
        } finally {
            pool.shutdown();
        }
    }

    @Test
    @DisplayName("10: ... and only when the code names it: an id is a user's, whatever it holds")
    void principals() {
        assertEquals(new Principal("user", "service:1"), Principal.user("service:1"));
        assertEquals(new Principal("service", "1"), Principal.of("service", 1));
        assertEquals(Principal.NOBODY, Principal.user(null));
        assertEquals(Principal.NOBODY, Principal.of("service", null));
        // what toString() wrote, read back, for text the app wrote itself (a job's argument): every principal as
        // itself, a user whose id holds a colon or is "nobody" too
        List<Principal> every = new ArrayList<>();
        for (String u : List.of("service:1", "nobody", "google-oauth2:117", "user:5", "a:b", ":", "(1,a:b)", "(1,2)", "",
                "42")) {
            every.add(Principal.user(u));
        }
        every.addAll(List.of(Principal.NOBODY, Principal.of("service", 1), Principal.of("service", "3:4"),
                Principal.of("service", "(1,2)")));
        assertEquals(every, every.stream().map(p -> Principal.parse(p.toString())).toList());
        assertEquals(List.of("user:service:1", "user:nobody", "42", "service:1", "nobody"),
                Stream.of(Principal.user("service:1"), Principal.user("nobody"), Principal.user(42),
                        Principal.of("service", 1), Principal.NOBODY).map(Principal::toString).toList());
        assertEquals(Principal.user("42"), Principal.parse("42"));
        assertEquals(Principal.user("(1,a:b)"), Principal.parse("(1,a:b)")); // a key of several columns is a user's
        // acting as someone inside acting as another: back to the first after
        Rowstile.actingAs(Principal.user(1), () -> {
            assertEquals(Principal.user(2), Rowstile.actingAs(Principal.user(2), () -> Rowstile.current().orElseThrow()));
            assertEquals(Optional.of(Principal.user(1)), Rowstile.current());
            return null;
        });
    }

    @Test
    @DisplayName("queries by permission: a set check, and one call for a list's buttons")
    void byPermission() {
        assertEquals(List.of(1L), call("GET", "/projects/editable", "3", null).ids());
        assertEquals("{\"1\":[\"edit\",\"view\"],\"3\":[\"view\"]}", call("GET", "/projects/buttons", "3", null).text());
    }

    @Test
    @DisplayName("an update the rules allow that matched nothing is 409: the row changed meanwhile")
    void changedMeanwhile() {
        Reply r = call("PATCH", "/stubborn/4", "3", null); // cy may edit note 4: not the rules' doing
        assertProblem(r, "conflict", "Conflict", 409,
                "the row changed since it was read, and the rules allow the change: read it again", null);
        assertNull(r.json().get("why"));
    }
}
