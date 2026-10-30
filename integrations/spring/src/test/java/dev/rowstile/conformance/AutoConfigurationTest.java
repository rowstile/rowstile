package dev.rowstile.conformance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.rowstile.Authz;
import dev.rowstile.DatabaseError;
import dev.rowstile.Errors;
import dev.rowstile.Principal;
import dev.rowstile.Rowstile;
import dev.rowstile.spring.PrincipalSource;
import dev.rowstile.spring.RowstileAutoConfiguration;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.DataSourceTransactionManagerAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.JdbcClientAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.JdbcTemplateAutoConfiguration;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The starter in apps other than the conformance app's: JDBC alone (JdbcClient and its transaction manager, no JPA),
 * with or without Spring Security, with a way of its own to say who the request is; and what it does when a
 * transaction can't begin, or can't be signed in.
 */
class AutoConfigurationTest extends Conformance {
    static final AutoConfigurations JDBC = AutoConfigurations.of(DataSourceAutoConfiguration.class,
            DataSourceTransactionManagerAutoConfiguration.class, JdbcTemplateAutoConfiguration.class,
            JdbcClientAutoConfiguration.class, RowstileAutoConfiguration.class);

    static ApplicationContextRunner app(String url) {
        return new ApplicationContextRunner()
                .withConfiguration(JDBC)
                .withClassLoader(new FilteredClassLoader("org.springframework.orm", "jakarta.persistence"))
                .withPropertyValues("spring.datasource.url=" + url);
    }

    static List<Long> projects(JdbcClient jdbc, PlatformTransactionManager tm) {
        return new TransactionTemplate(tm).execute(s ->
                jdbc.sql("SELECT id FROM app.projects ORDER BY id").query(Long.class).list());
    }

    @AfterEach
    void signOut() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("JDBC alone: each transaction signs in as Spring Security's user, or as whoever the code acts for")
    void jdbc() throws SQLException {
        seed();
        app(WORKER.appUrl()).run(ctx -> {
            JdbcClient jdbc = ctx.getBean(JdbcClient.class);
            PlatformTransactionManager tm = ctx.getBean(PlatformTransactionManager.class);
            assertEquals(List.of(3L), projects(jdbc, tm)); // nobody signed in
            SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                    "2", "secret", List.of())); // a user, by the name Spring Security knows them by
            assertEquals(List.of(2L, 3L), projects(jdbc, tm));
            SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.unauthenticated(
                    "2", "secret")); // not signed in yet: nobody
            assertEquals(List.of(3L), projects(jdbc, tm));
            assertEquals(List.of(1L, 3L), Rowstile.actingAs(Principal.user(1), () -> projects(jdbc, tm)));
            // a nested transaction (a savepoint) keeps the transaction's sign-in; a new one signs in again
            TransactionTemplate nested = new TransactionTemplate(tm);
            nested.setPropagationBehavior(TransactionDefinition.PROPAGATION_NESTED);
            TransactionTemplate inner = new TransactionTemplate(tm);
            inner.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
            assertEquals(List.of(List.of(1L, 3L), List.of(2L, 3L)), Rowstile.actingAs(Principal.user(1),
                    () -> new TransactionTemplate(tm).execute(s -> List.of(
                            nested.execute(n -> jdbc.sql("SELECT id FROM app.projects ORDER BY id").query(Long.class).list()),
                            Rowstile.actingAs(Principal.user(2), () -> inner.execute(n ->
                                    jdbc.sql("SELECT id FROM app.projects ORDER BY id").query(Long.class).list()))))));
            // the runtime's calls, in the transaction open now; outside one, a transaction nobody signed in to
            Authz authz = ctx.getBean(Authz.class);
            assertEquals(Boolean.TRUE, Rowstile.actingAs(Principal.user(1),
                    () -> new TransactionTemplate(tm).execute(s -> authz.can(AuthzNames.ProjectPermission.EDIT, 1))));
            DatabaseError outside = assertThrows(DatabaseError.class, () -> authz.can(AuthzNames.ProjectPermission.EDIT, 1));
            assertTrue(Errors.notSignedIn(outside), outside.toString());
        });
    }

    @Test
    @DisplayName("a transaction is one principal's: someone else's work can't join it, and it goes on as its own")
    void onePrincipal() throws SQLException {
        seed();
        app(WORKER.appUrl()).run(ctx -> {
            JdbcClient jdbc = ctx.getBean(JdbcClient.class);
            PlatformTransactionManager tm = ctx.getBean(PlatformTransactionManager.class);
            TransactionTemplate tx = new TransactionTemplate(tm);
            TransactionTemplate nested = new TransactionTemplate(tm);
            nested.setPropagationBehavior(TransactionDefinition.PROPAGATION_NESTED);
            List<String> ran = new ArrayList<>();
            List<Object> seen = Rowstile.actingAs(Principal.user(1), () -> tx.execute(s -> {
                // the same user's work joins it (and a savepoint of it), as it is
                List<Long> same = Rowstile.actingAs(Principal.user(1), () -> nested.execute(n -> projects(jdbc, tm)));
                // anyone else's is refused before it runs, joined or in a savepoint, and nothing is sent for it
                IllegalStateException other = assertThrows(IllegalStateException.class,
                        () -> Rowstile.actingAs(Principal.of("service", 1), () -> tx.execute(n -> ran.add("joined"))));
                IllegalStateException savepoint = assertThrows(IllegalStateException.class,
                        () -> Rowstile.actingAs(Principal.user(2), () -> nested.execute(n -> ran.add("savepoint"))));
                IllegalStateException nobody = assertThrows(IllegalStateException.class,
                        () -> Rowstile.actingAs(Principal.NOBODY, () -> tx.execute(n -> ran.add("nobody"))));
                // the transaction goes on as ann's: it reads and writes as hers, and commits
                int changed = jdbc.sql("UPDATE app.notes SET body = 'still ann''s' WHERE id = 1").update();
                return List.of(same, other.getMessage(), savepoint.getMessage(), nobody.getMessage(), changed,
                        signedIn(jdbc), projects(jdbc, tm));
            }));
            assertEquals(List.of(), ran);
            assertEquals(List.of(1L, 3L), seen.get(0));
            assertEquals("this transaction is signed in as 1 already, and a sign-in lasts the database transaction: "
                    + "service:1's work can't run inside it. Run it after, or in a transaction of its own (another "
                    + "connection)", seen.get(1));
            assertTrue(seen.get(2).toString().contains("signed in as 1 already") && seen.get(2).toString().contains(
                    ": 2's work can't run inside it"), seen.get(2).toString());
            assertTrue(seen.get(3).toString().contains(": the work of code that acts for no one can't run inside it. "
                    + "Run it after, or in a transaction of its own"), seen.get(3).toString());
            assertEquals(List.of(1, "1", List.of(1L, 3L)), seen.subList(4, 7));
            assertEquals(List.of("still ann's"), Rowstile.actingAs(Principal.user(1), () -> tx.execute(s ->
                    jdbc.sql("SELECT body FROM app.notes WHERE id = 1").query(String.class).list())));
            // a transaction of its own, after or on another connection, is the other's
            assertEquals(List.of(2L, 3L), Rowstile.actingAs(Principal.user(2), () -> projects(jdbc, tm)));
            // the manager the app gets stands in for Spring Boot's: itself, and no other
            assertEquals(tm, ctx.getBean(PlatformTransactionManager.class));
            assertNotEquals(tm, new Object());
            assertEquals(System.identityHashCode(tm), tm.hashCode());
        });
    }

    /** Who the transaction open now is signed in as, asked of the database. */
    static String signedIn(JdbcClient jdbc) {
        return jdbc.sql("SELECT current_setting('authz.user_id', true)").query(String.class).single();
    }

    @Test
    @DisplayName("without Spring Security, nobody, unless the app says who the request is")
    void withoutSecurity() throws SQLException {
        seed();
        app(WORKER.appUrl())
                .withClassLoader(new FilteredClassLoader("org.springframework.orm", "jakarta.persistence",
                        "org.springframework.security"))
                .run(ctx -> {
                    assertFalse(ctx.containsBean("rowstilePrincipalSource"));
                    assertEquals(List.of(3L), projects(ctx.getBean(JdbcClient.class),
                            ctx.getBean(PlatformTransactionManager.class)));
                });
        app(WORKER.appUrl())
                .withBean(PrincipalSource.class, () -> () -> Principal.user(2))
                .run(ctx -> assertEquals(List.of(2L, 3L), projects(ctx.getBean(JdbcClient.class),
                        ctx.getBean(PlatformTransactionManager.class))));
    }

    @Test
    @DisplayName("a transaction that can't begin is no one's; one that can't be signed in ends, and says why")
    void cantSignIn() throws SQLException {
        app("jdbc:postgresql://localhost:1/nothing")
                .withPropertyValues("rowstile.check-connection=false", "spring.datasource.hikari.connection-timeout=250")
                .run(ctx -> assertThrows(CannotCreateTransactionException.class,
                        () -> projects(ctx.getBean(JdbcClient.class), ctx.getBean(PlatformTransactionManager.class))));
        // with the check at start-up, the app doesn't start where it can't connect
        app("jdbc:postgresql://localhost:1/nothing")
                .withPropertyValues("spring.datasource.hikari.connection-timeout=250")
                .run(ctx -> assertTrue(StartupTest.cause(ctx.getStartupFailure(), DatabaseError.class).getMessage()
                        .contains("Connection to localhost:1 refused"), String.valueOf(ctx.getStartupFailure())));
        String empty = "conf_nopolicy_w" + System.getProperty("rowstile.worker", "0");
        String postgres = TESTS.replaceFirst("/conf_tests\\?", "/postgres?");
        try (Connection conn = DriverManager.getConnection(postgres); Statement st = conn.createStatement()) {
            st.execute("DROP DATABASE IF EXISTS " + empty);
            st.execute("CREATE DATABASE " + empty);
        }
        try {
            String url = TESTS.replaceFirst("/conf_tests\\?", "/" + empty + "?");
            app(url).withPropertyValues("rowstile.check-connection=false").run(ctx -> {
                for (int twice = 0; twice < 2; twice++) { // nothing of the first is left bound to the thread
                    CannotCreateTransactionException e = assertThrows(CannotCreateTransactionException.class,
                            () -> projects(ctx.getBean(JdbcClient.class), ctx.getBean(PlatformTransactionManager.class)));
                    assertTrue(e.getMessage().contains("could not be signed in"), e.getMessage());
                    assertInstanceOf(SQLException.class, e.getCause());
                    assertTrue(TransactionSynchronizationManager.getResourceMap().isEmpty());
                }
            });
            // and the app doesn't start there: the check can't ask
            app(url).run(ctx -> {
                assertTrue(ctx.getStartupFailure() != null);
                assertTrue(Errors.sqlState(ctx.getStartupFailure()).isPresent(), String.valueOf(ctx.getStartupFailure()));
            });
        } finally {
            try (Connection conn = DriverManager.getConnection(postgres); Statement st = conn.createStatement()) {
                st.execute("DROP DATABASE IF EXISTS " + empty + " WITH (FORCE)");
            }
        }
    }
}
