package dev.rowstile.conformance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.rowstile.Authz;
import dev.rowstile.Principal;
import dev.rowstile.Rowstile;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.function.BiFunction;
import java.util.stream.Stream;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.util.FileSystemUtils;

/**
 * Check 14: a policy change ships as the next migration, and the app's code works with the names the policy then
 * makes. On a database of its own, copied from the migrated test database.
 */
class PolicyChangeTest {
    static final Path HERE = GeneratedNamesTest.HERE;
    static final String DB = "conf_tests_w" + System.getProperty("rowstile.worker", "0") + "_14";

    static String url(String name) {
        return Conformance.TESTS.replaceFirst("/conf_tests\\?", "/" + name + "?");
    }

    @Test
    @DisplayName("14: after a policy change and a new migration, the app works with the new generated names")
    void policyChange(@TempDir Path tmp) throws Exception {
        Path work = tmp.resolve("app");
        for (String part : List.of("db", "rowstile.toml", "src/main/resources/db/migration")) {
            Files.createDirectories(work.resolve(part).getParent());
            FileSystemUtils.copyRecursively(HERE.resolve(part), work.resolve(part));
        }
        // the new names in a package of their own, beside the app's (which the tests' classes hold)
        Path toml = work.resolve("rowstile.toml");
        Files.writeString(toml, Files.readString(toml, StandardCharsets.UTF_8)
                .replace("src/main/java/dev/rowstile/conformance/AuthzNames.java", "src/main/java/check/AuthzNames.java"));
        Path policy = work.resolve("db/policy.authz");
        Files.writeString(policy, Files.readString(policy, StandardCharsets.UTF_8)
                .replace("  can read = recipient\n", "  can read = recipient\n  can reply = recipient\n"));
        try (Connection conn = DriverManager.getConnection(url("postgres")); Statement st = conn.createStatement()) {
            st.execute("DROP DATABASE IF EXISTS " + DB + " WITH (FORCE)");
            st.execute("CREATE DATABASE " + DB + " TEMPLATE conf_tests");
        }
        try {
            long message;
            try (Connection owner = DriverManager.getConnection(url(DB)); Statement st = owner.createStatement()) {
                st.execute("INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo')"); // ann sends bo a message
                try (ResultSet rs = st.executeQuery(
                        "INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES (1, 2, 'hi') RETURNING id")) {
                    rs.next();
                    message = rs.getLong(1);
                }
            }
            // the next migration is numbered after the folder's last (Flyway's V<n>__)
            int last;
            try (Stream<Path> files = Files.list(work.resolve("src/main/resources/db/migration"))) {
                last = files.map(f -> f.getFileName().toString())
                        .filter(n -> n.matches("V\\d+__.*\\.sql"))
                        .mapToInt(n -> Integer.parseInt(n.substring(1, n.indexOf("__"))))
                        .max()
                        .orElseThrow();
            }
            String said = Javac.rowstile(work, "migrate");
            assertTrue(said.contains("wrote src/main/resources/db/migration/V" + (last + 1) + "__authz_"), said);
            // Flyway migrates it, the way the app's start-up does
            Flyway.configure()
                    .dataSource(url(DB), null, null)
                    .locations("filesystem:" + work.resolve("src/main/resources/db/migration"))
                    .load()
                    .migrate();
            Javac.rowstile(work, "client");
            // the app's code, with the names the policy now makes: it names reply, and the database answers it
            String use = """
                    package check;

                    import dev.rowstile.Authz;
                    import check.AuthzNames.MessagePermission;
                    import java.util.List;

                    public class Reply implements java.util.function.BiFunction<Authz, Long, List<Boolean>> {
                        @Override
                        public List<Boolean> apply(Authz authz, Long message) {
                            return List.of(authz.can(MessagePermission.REPLY, message),
                                    authz.can(MessagePermission.READ, message));
                        }
                    }
                    """;
            Path out = Files.createDirectories(tmp.resolve("classes"));
            Javac.Said compiled = Javac.compile(out, Javac.classpath(), Javac.write(out.resolve("check/Reply.java"), use),
                    work.resolve("src/main/java/check/AuthzNames.java"));
            assertTrue(compiled.ok(), compiled.text());
            String app = url(DB).replaceFirst("user=conf_owner&password=owner", "user=conf_app&password=app");
            try (URLClassLoader loader = new URLClassLoader(new URL[] {out.toUri().toURL()}, getClass().getClassLoader())) {
                @SuppressWarnings("unchecked")
                BiFunction<Authz, Long, List<Boolean>> reply = (BiFunction<Authz, Long, List<Boolean>>)
                        loader.loadClass("check.Reply").getDeclaredConstructor().newInstance();
                try (Connection conn = DriverManager.getConnection(app)) {
                    // bo, to whom it is sent, may reply; ann, who sent it, may not even read it
                    List<List<Boolean>> said2 = List.of(Rowstile.transaction(conn, Principal.user(2),
                                    c -> reply.apply(Authz.on(c), message)),
                            Rowstile.transaction(conn, Principal.user(1), c -> reply.apply(Authz.on(c), message)));
                    assertEquals(List.of(List.of(true, true), List.of(false, false)), said2);
                    // the names from before the change don't know reply: the SDK says to write them again
                    IllegalStateException stale = assertThrows(IllegalStateException.class, () -> Rowstile.transaction(
                            conn, Principal.user(2), c -> Authz.on(c).perms(AuthzNames.MESSAGE, message)));
                    assertTrue(stale.getMessage().contains("write the names again"), stale.getMessage());
                }
            }
        } finally {
            try (Connection conn = DriverManager.getConnection(url("postgres")); Statement st = conn.createStatement()) {
                st.execute("DROP DATABASE IF EXISTS " + DB + " WITH (FORCE)");
            }
        }
    }
}
