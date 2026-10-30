package dev.rowstile.conformance

import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Check 9: the policy's names (rowstile client java), used from Kotlin, so a wrong one doesn't compile. */
class GeneratedNamesTest {
    companion object {
        val HERE: Path = Path.of(System.getProperty("basedir", "."))
        val NAMES: Path = Path.of("src/main/java/dev/rowstile/conformance/AuthzNames.java")
    }

    @Test
    @DisplayName("9: the generated names type-check, and a wrong permission name doesn't: in the names and in the SDK's calls")
    fun names(@TempDir tmp: Path) {
        // the committed names are the ones the policy makes (rowstile client java POLICY prints them, and writes nothing)
        val made = Kotlinc.rowstile(HERE, "client", "java", "db/policy.authz")
        assertEquals(Files.readString(HERE.resolve(NAMES)), made, "AuthzNames.java is out of date: run rowstile client")
        val use = """
            package check

            import dev.rowstile.Authz
            import dev.rowstile.conformance.AuthzNames
            import dev.rowstile.conformance.AuthzNames.NotePermission

            fun can(authz: Authz): Boolean {
                val held: List<NotePermission> = authz.perms(AuthzNames.%s, 1)
                return NotePermission.EDIT in held && authz.can(NotePermission.%s, 1)
            }
        """.trimIndent()
        for ((type, perm, error) in listOf(
            Triple("NOTE", "EDIT", ""),
            Triple("NOTE", "EDT", "unresolved reference 'EDT'"),
            Triple("NTE", "EDIT", "unresolved reference 'NTE'"),
            Triple("PROJECT", "VIEW", "type mismatch"),
        )) {
            val out = Files.createDirectories(tmp.resolve(type + perm))
            val said = Kotlinc.kotlin(out, Kotlinc.write(out.resolve("check/Use.kt"), use.format(type, perm)))
            if (error.isEmpty()) {
                assertTrue(said.ok, said.text)
            } else {
                assertFalse(said.ok, "compiled: $type $perm")
                assertTrue(said.text.contains(error), said.text)
            }
        }
    }
}
