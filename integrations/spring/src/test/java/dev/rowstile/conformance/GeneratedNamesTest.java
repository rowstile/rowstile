package dev.rowstile.conformance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Check 9: the policy's names are Java's, so a wrong one doesn't compile. */
class GeneratedNamesTest {
    static final Path HERE = Path.of(System.getProperty("basedir", "."));
    static final Path NAMES = Path.of("src/main/java/dev/rowstile/conformance/AuthzNames.java");

    @Test
    @DisplayName("9: the generated names type-check, and a wrong permission name doesn't: in the names and in the SDK's calls")
    void names(@TempDir Path tmp) throws Exception {
        // the committed names are the ones the policy makes (rowstile client java POLICY prints them, and writes nothing)
        String made = Javac.rowstile(HERE, "client", "java", "db/policy.authz");
        assertEquals(Files.readString(HERE.resolve(NAMES), StandardCharsets.UTF_8), made,
                "AuthzNames.java is out of date: run rowstile client");
        String use = """
                package check;

                import dev.rowstile.Authz;
                import dev.rowstile.conformance.AuthzNames;
                import dev.rowstile.conformance.AuthzNames.NotePermission;
                import java.util.List;

                class Use {
                    static boolean can(Authz authz) {
                        List<NotePermission> held = authz.perms(AuthzNames.%s, 1);
                        return held.contains(NotePermission.EDIT) && authz.can(NotePermission.%s, 1);
                    }
                }
                """;
        for (List<String> each : List.of(List.of("NOTE", "EDIT", ""), List.of("NOTE", "EDT", "EDT"),
                List.of("NTE", "EDIT", "NTE"), List.of("PROJECT", "VIEW", "incompatible types"))) {
            Path out = Files.createDirectories(tmp.resolve(each.get(0) + each.get(1)));
            Path source = Javac.write(out.resolve("check/Use.java"), use.formatted(each.get(0), each.get(1)));
            Javac.Said said = Javac.compile(out, Javac.classpath(), source);
            if (each.get(2).isEmpty()) {
                assertTrue(said.ok(), said.text());
            } else {
                assertFalse(said.ok(), "compiled: " + each);
                assertTrue(said.text().contains(each.get(2)), said.text());
            }
        }
    }
}
