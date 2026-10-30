package dev.rowstile.conformance

import org.jetbrains.kotlin.cli.common.ExitCode
import org.jetbrains.kotlin.cli.jvm.K2JVMCompiler
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.io.StringWriter
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import javax.tools.ToolProvider

/** Kotlin's compiler and javac, as the app's build runs them (every warning an error), and the command. */
object Kotlinc {
    /** What the compiler said, and whether it compiled. */
    data class Said(val ok: Boolean, val text: String)

    /** The tests' own classpath: the SDK, Ktor, Exposed, the app's classes. */
    val classpath: String = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"))

    /** Compiles the Kotlin [sources] into [out], against [classpath] and [more]. */
    fun kotlin(out: Path, vararg sources: Path, more: List<Path> = listOf()): Said {
        val said = ByteArrayOutputStream()
        val cp = (more.map(Path::toString) + classpath).joinToString(File.pathSeparator)
        val args = arrayOf("-no-stdlib", "-no-reflect", "-Werror", "-jvm-target", "21", "-classpath", cp, "-d", "$out") +
            sources.map(Path::toString)
        val code = PrintStream(said, true, Charsets.UTF_8).use { K2JVMCompiler().exec(it, *args) }
        return Said(code == ExitCode.OK, said.toString(Charsets.UTF_8))
    }

    /** Compiles the Java [sources] into [out] (the generated names), against [classpath]. */
    fun java(out: Path, vararg sources: Path): Said {
        val javac = ToolProvider.getSystemJavaCompiler()
        val said = StringWriter()
        val args = listOf("-Xlint:all", "-Werror", "-proc:none", "-d", "$out", "-cp", classpath)
        val ok = javac.getStandardFileManager(null, null, Charsets.UTF_8).use { files ->
            javac.getTask(said, files, null, args, null, files.getJavaFileObjects(*sources)).call()
        }
        return Said(ok, said.toString())
    }

    fun write(file: Path, text: String): Path {
        Files.createDirectories(file.parent)
        return Files.writeString(file, text)
    }

    /** The rowstile command (test.sh's ROWSTILE_CLI), run in [dir]: what it printed. */
    fun rowstile(dir: Path, vararg args: String): String {
        val p = ProcessBuilder(System.getenv("ROWSTILE_CLI").split(" ") + args)
            .directory(dir.toFile())
            .redirectErrorStream(true)
            .start()
        val out = p.inputStream.readAllBytes().toString(Charsets.UTF_8)
        check(p.waitFor(120, TimeUnit.SECONDS) && p.exitValue() == 0) { "rowstile ${args.joinToString(" ")}: $out" }
        return out
    }
}
