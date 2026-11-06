package dev.rowstile.spring;

import dev.rowstile.Authz;
import dev.rowstile.Refused;
import jakarta.persistence.EntityManager;
import jakarta.persistence.OptimisticLockException;
import java.util.List;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import org.hibernate.StaleObjectStateException;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.metamodel.mapping.CompositeIdentifierMapping;
import org.hibernate.metamodel.mapping.EntityIdentifierMapping;
import org.hibernate.persister.entity.EntityPersister;
import org.springframework.dao.support.DataAccessUtils;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.TransactionExecution;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * The sign-in for JPA's transactions on Hibernate, and why a flush changed nothing. Row-level security skips the rows
 * a user may not update or delete without an error, so Hibernate finds that its statement matched no row. Before the
 * commit, this flushes, and asks the database why in the same transaction: {@link Refused} with the rule and the
 * reason (403), {@link dev.rowstile.NotFound} when the user can't see the row (404), or {@link Conflict} when the
 * rules allow the change (the row changed since it was read: 409). An entity whose id has several columns is a
 * {@link Refused} without a reason, and nothing is asked ({@link #answer}).
 */
final class HibernateSignIn extends JpaSignIn {
    /**
     * A DELETE, in Hibernate's message about the statement that matched no row: "Unexpected row count (...) [delete
     * from app.notes where id=?]", the statement after any comment before it ({@code hibernate.use_sql_comments}).
     */
    private static final Pattern DELETE = Pattern.compile("\\[\\s*(?:/\\*[^*]*\\*+(?:[^/*][^*]*\\*+)*/\\s*)*delete\\b",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    private final Supplier<Authz> authz;

    HibernateSignIn(JpaTransactionManager manager, Supplier<PrincipalSource> source, Supplier<Authz> authz) {
        super(manager, source);
        this.authz = authz;
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
        EntityPersister entity = em.getEntityManagerFactory()
                .unwrap(SessionFactoryImplementor.class)
                .getMappingMetamodel()
                .getEntityDescriptor(stale.getEntityName());
        String table = entity.getMappedTableDetails().getTableName();
        // the statement the database ran, which its rules refused: a soft delete's (@SQLDelete) is an UPDATE
        String command = DELETE.matcher(String.valueOf(stale.getMessage())).find() ? "delete" : "update";
        return answer(entity.getIdentifierMapping(), table, command,
                () -> authz.get().verdict(table, command, stale.getIdentifier()), e);
    }

    /**
     * The answer to a write of {@code table} that matched no row: the database's ({@code ask}), for an entity whose
     * id is one column; for one whose id has several (an {@code @EmbeddedId}, an {@code @IdClass}), a refusal of the
     * {@code command} that says nothing of why, since nothing is asked. The id's columns are in the order Hibernate
     * keeps them (alphabetical), which needn't be the policy's key's, and a row named by another order is another row.
     */
    static RuntimeException answer(EntityIdentifierMapping id, String table, String command,
            Supplier<Authz.Verdict> ask, Throwable e) {
        if (id instanceof CompositeIdentifierMapping) {
            return new Refused("permission denied: this user may not " + command + " the row of " + table
                    + " (a key of several columns: not asked why)", table, command, List.of(), null, e);
        }
        Authz.Verdict verdict = ask.get();
        return verdict.allowed() ? new Conflict(e) : verdict.error();
    }
}
