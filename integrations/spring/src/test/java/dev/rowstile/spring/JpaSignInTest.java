package dev.rowstile.spring;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.rowstile.Principal;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.OptimisticLockException;
import java.lang.reflect.Proxy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.orm.jpa.JpaOptimisticLockingFailureException;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.TransactionExecution;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** What the flush before the commit leaves alone: a version check of the JPA provider's own (a lock). */
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
        JpaSignIn signIn = new JpaSignIn(manager, () -> () -> Principal.NOBODY, () -> null);
        TransactionSynchronizationManager.bindResource(emf, new EntityManagerHolder(stand(EntityManager.class, lock)));
        try {
            ObjectOptimisticLockingFailureException e = assertThrows(JpaOptimisticLockingFailureException.class,
                    () -> signIn.beforeCommit(stand(TransactionExecution.class)));
            assertSame(lock, e.getCause());
        } finally {
            TransactionSynchronizationManager.unbindResource(emf);
        }
    }
}
