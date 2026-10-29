package dev.rowstile.conformance;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

/** javac, as the app's build runs it (every warning an error), and the command, for the checks on names. */
final class Javac {
    private Javac() {}

    /** What javac said, and whether it compiled. */
    record Said(boolean ok, String text) {}

    /** The tests' own classpath: the SDK, Spring, the app's classes. */
    static String classpath() {
        return System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
    }

    /** Compiles {@code sources} into {@code out}, against {@code classpath}. */
    static Said compile(Path out, String classpath, Path... sources) throws IOException {
        JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
        StringWriter said = new StringWriter();
        List<String> args = List.of("-Xlint:all", "-Werror", "-proc:none", "-d", out.toString(), "-cp", classpath);
        try (StandardJavaFileManager files = javac.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
            boolean ok = javac.getTask(said, files, null, args, null, files.getJavaFileObjects(sources)).call();
            return new Said(ok, said.toString());
        }
    }

    static Path write(Path file, String text) throws IOException {
        Files.createDirectories(file.getParent());
        return Files.writeString(file, text, StandardCharsets.UTF_8);
    }

    /** The rowstile command (test.sh's ROWSTILE_CLI), run in {@code dir}: what it printed. */
    static String rowstile(Path dir, String... args) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>(List.of(System.getenv("ROWSTILE_CLI").split(" ")));
        command.addAll(List.of(args));
        Process p = new ProcessBuilder(command).directory(dir.toFile()).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!p.waitFor(120, TimeUnit.SECONDS) || p.exitValue() != 0) {
            throw new IllegalStateException("rowstile " + String.join(" ", args) + ": " + out);
        }
        return out;
    }
}
