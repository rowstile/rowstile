package dev.rowstile.conformance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.rowstile.ConnectionProblem;
import dev.rowstile.DatabaseError;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.event.ContextRefreshedEvent;

/** Check 13: the app doesn't start on a connection where the database would filter nothing. */
class StartupTest {
    static ConfigurableApplicationContext start(List<String> served, String datasource, String... more) {
        // as the command line gives them: they come before application.properties
        List<String> args = new ArrayList<>(List.of("--spring.datasource.url=" + datasource,
                "--spring.flyway.url=" + Conformance.WORKER.url(), "--server.port=0"));
        for (String m : more) {
            args.add("--" + m);
        }
        return new SpringApplicationBuilder(ConformanceApp.class)
                .listeners(e -> {
                    if (e instanceof ContextRefreshedEvent) {
                        served.add("served"); // the web server starts, and the app serves, after this
                    }
                })
                .run(args.toArray(String[]::new));
    }

    static <T extends Throwable> T cause(Throwable e, Class<T> type) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (type.isInstance(t)) {
                return type.cast(t);
            }
        }
        throw new AssertionError("no " + type.getSimpleName() + " in " + e, e);
    }

    @Test
    @DisplayName("13: the app refuses to start on a connection that skips row-level security")
    void refusesTheOwner() {
        List<String> served = new ArrayList<>();
        Exception e = assertThrows(Exception.class, () -> start(served, Conformance.WORKER.url()).close());
        ConnectionProblem problem = cause(e, ConnectionProblem.class);
        assertTrue(problem.getMessage().contains("an owner skips row-level security"), problem.getMessage());
        assertTrue(problem.problems().stream().allMatch(p -> p.contains("conf_owner")), problem.problems().toString());
        assertEquals(List.of(), served);
        // and on the app role's connection it starts
        try (ConfigurableApplicationContext app = start(served, Conformance.WORKER.appUrl())) {
            assertTrue(app.isRunning());
        }
        assertEquals(List.of("served"), served);
    }

    @Test
    @DisplayName("13: ... nor on a database without the policy, which can't be asked")
    void refusesNoPolicy() throws Exception {
        String empty = "conf_empty_w" + System.getProperty("rowstile.worker", "0");
        String postgres = Conformance.TESTS.replaceFirst("/conf_tests\\?", "/postgres?");
        try (Connection conn = DriverManager.getConnection(postgres); Statement st = conn.createStatement()) {
            st.execute("DROP DATABASE IF EXISTS " + empty);
            st.execute("CREATE DATABASE " + empty);
        }
        try {
            String url = Conformance.TESTS.replaceFirst("/conf_tests\\?", "/" + empty + "?");
            Exception e = assertThrows(Exception.class,
                    () -> start(new ArrayList<>(), url, "spring.flyway.enabled=false",
                            "spring.jpa.hibernate.ddl-auto=none").close());
            DatabaseError error = cause(e, DatabaseError.class);
            assertInstanceOf(java.sql.SQLException.class, error.getCause());
            assertTrue(error.getMessage().contains("schema \"authz\" does not exist"), error.getMessage());
        } finally {
            try (Connection conn = DriverManager.getConnection(postgres); Statement st = conn.createStatement()) {
                st.execute("DROP DATABASE IF EXISTS " + empty + " WITH (FORCE)");
            }
        }
    }
}
