package dev.rowstile.conformance;

import static org.junit.jupiter.api.Assertions.assertEquals;

import dev.rowstile.testing.WorkerDatabase;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * What the checks share: this JVM's own database (check 12), copied once from the migrated test database, with the
 * same few rows for every test; and requests to the app, as a user or a service, the way a browser would send them.
 */
abstract class Conformance {
    /** The migrated test database (test.sh's conf_tests), as the owner; and the app role's URL. */
    static final String TESTS = System.getenv("ROWSTILE_TESTS_URL");
    static final String APP = System.getenv("ROWSTILE_APP_URL");
    /** This JVM's copy of it, made once (check 12). */
    static final WorkerDatabase WORKER = WorkerDatabase.copy(TESTS, null, null, APP, true);
    static final JsonMapper JSON = JsonMapper.builder().build();
    static final HttpClient HTTP = HttpClient.newHttpClient();
    /** The notes each may see; the projects. */
    static final Map<String, List<Long>> NOTES = Map.of("1", List.of(1L, 3L, 4L), "2", List.of(2L, 3L), "3",
            List.of(1L, 3L, 4L), "", List.of(3L));

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", WORKER::appUrl);
        registry.add("spring.flyway.url", WORKER::url);
    }

    static Connection owner() throws SQLException {
        return DriverManager.getConnection(WORKER.url());
    }

    /** As the owner, in a transaction of its own. */
    static void sql(String... statements) throws SQLException {
        try (Connection conn = owner(); Statement st = conn.createStatement()) {
            for (String s : statements) {
                st.execute(s);
            }
        }
    }

    /**
     * The same few rows for every test: ann (1) owns project 1 (cy is a member, service 1 reads it) and the public
     * project 3; bo (2) owns project 2. Ann's folder 1 has folder 2 inside it.
     */
    static void seed() throws SQLException {
        sql("TRUNCATE app.folders, app.inbox, app.notes, app.members, app.project_services, app.projects, app.services,"
                        + " app.users CASCADE",
                "INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo'), (3, 'cy')",
                "INSERT INTO app.services VALUES (1, 'digest')",
                "INSERT INTO app.projects VALUES (1, 1, 'Plans', false), (2, 2, 'Bo''s', false), (3, 1, 'Open', true)",
                "INSERT INTO app.members VALUES (1, 3)",
                "INSERT INTO app.project_services VALUES (1, 1)",
                "INSERT INTO app.notes (id, project_id, author_id, body) VALUES (1, 1, 1, 'plan'), (2, 2, 2, 'mine'),"
                        + " (3, 3, 1, 'hello'), (4, 1, 3, 'idea')",
                "SELECT setval(pg_get_serial_sequence('app.notes', 'id'), 100)",
                "INSERT INTO app.folders VALUES (1, NULL, 1, 'top'), (2, 1, 1, 'inside')");
    }

    /** An answer: its status, its content type, and its body (JSON, if it is). */
    record Reply(int status, String type, String text) {
        JsonNode json() {
            return JSON.readTree(text);
        }

        List<Long> ids() {
            return json().valueStream().map(JsonNode::asLong).toList();
        }
    }

    /** A request to the app on {@code port}: {@code who} is a user's id, {@code service:1} a service, or none. */
    static CompletableFuture<Reply> send(int port, String method, String path, String who, Object body,
            Map<String, String> headers) {
        HttpRequest.Builder r = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .method(method, body == null
                        ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)))
                .header("content-type", "application/json");
        if (who != null && who.startsWith("service:")) {
            r.header("x-service", who.substring(8));
        } else if (who != null) {
            r.header("x-user", who);
        }
        headers.forEach(r::header);
        return HTTP.sendAsync(r.build(), HttpResponse.BodyHandlers.ofString()).thenApply(a -> new Reply(a.statusCode(),
                a.headers().firstValue("content-type").orElse(""), a.body()));
    }

    static Reply call(int port, String method, String path, String who, Object body) {
        return call(port, method, path, who, body, Map.of());
    }

    static Reply call(int port, String method, String path, String who, Object body, Map<String, String> headers) {
        try {
            return send(port, method, path, who, body, headers).get();
        } catch (InterruptedException | java.util.concurrent.ExecutionException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A problem body, as the SDKs send it: its type, title, status, detail and code. */
    static void assertProblem(Reply r, String kind, String title, int status, String detail, String code) {
        assertEquals(status, r.status(), r.text());
        assertEquals("application/problem+json", r.type(), r.text());
        JsonNode p = r.json();
        assertEquals("https://rowstile.dev/problems/" + kind, p.get("type").asString(), r.text());
        assertEquals(title, p.get("title").asString(), r.text());
        assertEquals(status, p.get("status").asInt(), r.text());
        assertEquals(detail, p.get("detail").asString(), r.text());
        assertEquals(code, p.has("code") ? p.get("code").asString() : null, r.text());
    }
}
