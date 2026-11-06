package dev.rowstile.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.rowstile.Authz;
import dev.rowstile.NotFound;
import dev.rowstile.Principal;
import dev.rowstile.Refused;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.OptimisticLockException;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.hibernate.metamodel.mapping.CompositeIdentifierMapping;
import org.hibernate.metamodel.mapping.EntityIdentifierMapping;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.orm.jpa.JpaOptimisticLockingFailureException;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.TransactionExecution;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * What the flush before the commit leaves alone: a version check of the JPA provider's own (a lock). And JPA's
 * transaction managers as the starter hands them out, and its answers for a handler of the app's own.
 */
class JpaSignInTest {
    static <T> T stand(Class<T> type, Object... answers) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, (p, m, a) -> {
            return switch (m.getName()) {
                case "flush" -> throw (RuntimeException) answers[0];
                case "hashCode" -> System.identityHashCode(p);
                case "equals" -> p == a[0];
                case "toString" -> "a stand-in " + type.getSimpleName();
                default -> m.getReturnType() == boolean.class ? Boolean.FALSE : null;
            };
        }));
    }

    @Test
    @DisplayName("a version check that isn't a statement that matched no row is the app's, as JPA's commit throws it")
    void lockIsTheApps() {
        OptimisticLockException lock = new OptimisticLockException("a lock");
        EntityManagerFactory emf = stand(EntityManagerFactory.class, lock);
        JpaTransactionManager manager = new JpaTransactionManager(emf);
        HibernateSignIn signIn = new HibernateSignIn(manager, () -> () -> Principal.NOBODY, () -> null);
        TransactionSynchronizationManager.bindResource(emf, new EntityManagerHolder(stand(EntityManager.class, lock)));
        try {
            ObjectOptimisticLockingFailureException e = assertThrows(JpaOptimisticLockingFailureException.class,
                    () -> signIn.beforeCommit(stand(TransactionExecution.class)));
            assertSame(lock, e.getCause());
        } finally {
            TransactionSynchronizationManager.unbindResource(emf);
        }
    }

    @Test
    @DisplayName("an entity whose id has several columns is refused without asking why; one of one column is asked")
    void severalColumns() {
        OptimisticLockException lock = new OptimisticLockException("matched no row");
        // an @EmbeddedId's or an @IdClass's: Hibernate's columns aren't the policy's key's order, so nothing is asked
        Refused composite = assertInstanceOf(Refused.class, HibernateSignIn.answer(
                stand(CompositeIdentifierMapping.class), "app.members", "delete", () -> {
                    throw new AssertionError("the database was asked");
                }, lock));
        assertEquals(List.of("app.members", "delete", List.of(), "AZ709", 403), List.of(composite.table(),
                composite.command(), composite.why(), composite.code(), composite.problem().status()));
        assertEquals("permission denied: this user may not delete the row of app.members (a key of several columns:"
                + " not asked why)", composite.getMessage());
        assertSame(lock, composite.getCause());
        // a key of one column: the database's answer
        Refused one = assertInstanceOf(Refused.class, HibernateSignIn.answer(stand(EntityIdentifierMapping.class),
                "app.notes", "update", () -> new Authz.Verdict("app.notes", "update", 1, List.of("no   edit"),
                        "user 3"), lock));
        assertEquals(List.of("permission denied: user 3 may not update row 1 of app.notes", List.of("no   edit")),
                List.of(one.getMessage(), one.why()));
    }

    @Test
    @DisplayName("a JPA transaction manager as the starter hands it out: made by its constructor, holding what it held")
    void guarded() {
        EntityManagerFactory emf = stand(EntityManagerFactory.class, new OptimisticLockException());
        JpaTransactionManager manager = new JpaTransactionManager(emf);
        manager.setJpaPropertyMap(Map.of("jakarta.persistence.lock.timeout", 100));
        Object bean = new SignInJpaTransactions(new SignInTransactions(null), null)
                .postProcessAfterInitialization(manager, "transactionManager");
        JpaTransactionManager guarded = (JpaTransactionManager) bean;
        assertNotEquals(JpaTransactionManager.class, guarded.getClass());
        assertEquals(List.of(emf, Map.of("jakarta.persistence.lock.timeout", 100)),
                List.of(guarded.getEntityManagerFactory(), guarded.getJpaPropertyMap()));
        // its final field is its own, the one its constructor made: not written by reflection
        guarded.getJpaPropertyMap().put("more", 1);
        assertEquals(Map.of("jakarta.persistence.lock.timeout", 100), manager.getJpaPropertyMap());
    }

    @Test
    @DisplayName("on another JPA provider than Hibernate, JPA's transactions are signed in all the same")
    void withoutHibernate() {
        EntityManagerFactory emf = stand(EntityManagerFactory.class, new OptimisticLockException());
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(DataSourceAutoConfiguration.class,
                        RowstileAutoConfiguration.class))
                .withClassLoader(new FilteredClassLoader("org.hibernate"))
                .withPropertyValues("spring.datasource.url=jdbc:postgresql://localhost:1/nothing",
                        "rowstile.check-connection=false")
                .withBean("transactionManager", JpaTransactionManager.class, () -> new JpaTransactionManager(emf))
                .run(ctx -> {
                    JpaTransactionManager tm = ctx.getBean(JpaTransactionManager.class);
                    assertNotEquals(JpaTransactionManager.class, tm.getClass());
                    List<Object> listeners = tm.getTransactionExecutionListeners().stream()
                            .map(l -> (Object) l.getClass()).toList();
                    assertEquals(List.of(JpaSignIn.class), listeners); // the flush that says why is Hibernate's
                });
    }

    @Test
    @DisplayName("a handler of the app's own (a catch-all) gives rowstile's answers first, as the starter's would")
    void problems() {
        ResponseEntity<ProblemDetail> gone = Problems.problem(new NotFound("app.notes", 7)).map(Problems::response)
                .orElseThrow();
        assertEquals(List.of(404, MediaType.APPLICATION_PROBLEM_JSON, "app.notes 7 not found"),
                List.of(gone.getStatusCode().value(), gone.getHeaders().getContentType(), gone.getBody().getDetail()));
        Optional<ResponseEntity<ProblemDetail>> changed = Problems.problem(new Conflict(new OptimisticLockException()))
                .map(Problems::response);
        assertEquals(409, changed.orElseThrow().getStatusCode().value());
        // the app's own mistake is none of rowstile's
        assertEquals(Optional.empty(), Problems.problem(new IllegalStateException("the app's")));
    }
}
