package dev.rowstile.spring;

import dev.rowstile.Authz;
import jakarta.persistence.EntityManager;
import jakarta.persistence.OptimisticLockException;
import java.util.Locale;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.hibernate.StaleObjectStateException;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.springframework.dao.support.DataAccessUtils;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.TransactionExecution;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * The sign-in for JPA's transactions, and why a flush changed nothing. Row-level security skips the rows a user may
 * not update or delete without an error, so Hibernate finds that its statement matched no row. Before the commit,
 * this flushes, and asks the database why in the same transaction: {@link dev.rowstile.Refused} with the rule and the
 * reason (403), {@link dev.rowstile.NotFound} when the user can't see the row (404), or {@link Conflict} when the
 * rules allow the change (the row changed since it was read: 409).
 */
final class JpaSignIn extends SignIn {
    private final Supplier<Authz> authz;

    JpaSignIn(JpaTransactionManager manager, Supplier<PrincipalSource> source, Supplier<Authz> authz) {
        super(manager, source);
        this.authz = authz;
    }

    private JpaTransactionManager jpa() {
        return (JpaTransactionManager) manager();
    }

    @Override
    DataSource dataSource() {
        return jpa().getDataSource();
    }

    @Override
    public void beforeCommit(TransactionExecution transaction) {
        if (transaction.isReadOnly()) {
            return;
        }
        EntityManagerHolder holder = (EntityManagerHolder)
                TransactionSynchronizationManager.getResource(jpa().getEntityManagerFactory());
        EntityManager em = holder.getEntityManager();
        try {
            em.flush();
        } catch (RuntimeException e) {
            if (e instanceof OptimisticLockException locked && e.getCause() instanceof StaleObjectStateException stale) {
                throw why(em, stale, locked);
            }
            // anything else (Hibernate's own version checks, a constraint) as the commit would have thrown it
            throw DataAccessUtils.translateIfNecessary(e, jpa().getJpaDialect());
        }
    }

    private RuntimeException why(EntityManager em, StaleObjectStateException stale, OptimisticLockException e) {
        String table = em.getEntityManagerFactory()
                .unwrap(SessionFactoryImplementor.class)
                .getMappingMetamodel()
                .getEntityDescriptor(stale.getEntityName())
                .getMappedTableDetails()
                .getTableName();
        // Hibernate's message holds the statement: "Unexpected row count (...) [delete from app.notes where id=?]"
        String said = String.valueOf(stale.getMessage()).toLowerCase(Locale.ROOT);
        String command = said.contains("[delete ") ? "delete" : "update";
        Authz.Verdict verdict = authz.get().verdict(table, command, stale.getIdentifier());
        return verdict.allowed() ? new Conflict(e) : verdict.error();
    }
}
