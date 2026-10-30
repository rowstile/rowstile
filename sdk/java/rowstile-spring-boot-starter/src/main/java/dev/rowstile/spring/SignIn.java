package dev.rowstile.spring;

import dev.rowstile.Principal;
import dev.rowstile.Rowstile;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionExecution;
import org.springframework.transaction.TransactionExecutionListener;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.ResourceTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.ClassUtils;

/**
 * Signs each transaction a transaction manager begins in, as its first statement: as whoever the code acts for
 * ({@link Rowstile#actingAs}, a job), else whoever the request is ({@link PrincipalSource}), else nobody. The sign-in
 * lasts the transaction: a pooled connection carries no one into the next.
 *
 * <p>A transaction is one principal's. Work that joins the transaction open now (a {@code @Transactional} method, a
 * {@code TransactionTemplate}, a repository's call, a savepoint: {@code NESTED}) runs as it is when the code acts for
 * the principal it signed in as; for anyone else, it is refused before anything is sent for it (an {@link
 * IllegalStateException}), and the transaction is left as it was. A transaction of its own ({@code REQUIRES_NEW},
 * another connection) signs in as whoever it is for.
 */
class SignIn implements TransactionExecutionListener {
    /** Whom each open transaction signed in as, by the resource it holds (its connection's, its entity manager's). */
    private static final Map<Object, Principal> SIGNED = Collections.synchronizedMap(new WeakHashMap<>());

    /** The ways of running work that join a transaction open now, rather than begin one of their own. */
    private static final Set<Integer> JOINS = Set.of(TransactionDefinition.PROPAGATION_REQUIRED,
            TransactionDefinition.PROPAGATION_SUPPORTS, TransactionDefinition.PROPAGATION_MANDATORY,
            TransactionDefinition.PROPAGATION_NESTED);

    private final ResourceTransactionManager manager;
    private final Supplier<DataSource> dataSource;
    private final Supplier<PrincipalSource> source;

    SignIn(ResourceTransactionManager manager, Supplier<DataSource> dataSource, Supplier<PrincipalSource> source) {
        this.manager = manager;
        this.dataSource = dataSource;
        this.source = source;
    }

    /** Whom the code running now acts for. */
    private Principal who() {
        return Rowstile.current().orElseGet(() -> source.get().principal());
    }

    @Override
    public void afterBegin(TransactionExecution transaction, @Nullable Throwable beginFailure) {
        if (beginFailure != null || !transaction.isNewTransaction()) {
            return;
        }
        Principal who = who();
        DataSource ds = dataSource.get();
        Connection conn = DataSourceUtils.getConnection(ds);
        SQLException refused = null;
        try {
            Rowstile.signIn(conn, who);
        } catch (SQLException e) {
            refused = e;
        } finally {
            DataSourceUtils.releaseConnection(conn, ds);
        }
        if (refused != null) {
            // begun, and not signed in: ended here, so that nothing is left bound to the thread
            manager.rollback((TransactionStatus) transaction);
            throw new CannotCreateTransactionException("the transaction could not be signed in (authz.act_as)", refused);
        }
        SIGNED.put(TransactionSynchronizationManager.getResource(manager.getResourceFactory()), who);
    }

    /**
     * Before {@code definition}'s work joins the transaction open now: refused if that transaction is signed in as
     * someone else than whoever the code acts for.
     */
    void enter(TransactionDefinition definition) {
        if (!JOINS.contains(definition.getPropagationBehavior())) {
            return;
        }
        Object held = TransactionSynchronizationManager.isActualTransactionActive()
                ? TransactionSynchronizationManager.getResource(manager.getResourceFactory())
                : null;
        Principal signed = SIGNED.get(held);
        if (signed != null) {
            Principal who = who();
            if (!signed.equals(who)) {
                throw signedInAlready(signed, who);
            }
        }
    }

    /** The error for work of {@code who}'s inside a transaction signed in as {@code signed}. */
    static IllegalStateException signedInAlready(Principal signed, Principal who) {
        String whose = who.nobody() ? "the work of code that acts for no one can't" : who + "'s work can't";
        return new IllegalStateException("this transaction is signed in as " + signed + " already, and a sign-in "
                + "lasts the database transaction: " + whose + " run inside it. Run it after, or in a transaction of "
                + "its own (another connection)");
    }

    /**
     * The transaction manager the app's code gets: {@code manager} itself, but for {@link
     * PlatformTransactionManager#getTransaction}, which first asks {@link #enter}. (Spring calls no listener when work
     * joins a transaction, and its {@code getTransaction} is final.)
     */
    Object guard(PlatformTransactionManager manager) {
        Class<?>[] types = ClassUtils.getAllInterfacesForClass(manager.getClass(), manager.getClass().getClassLoader());
        return Proxy.newProxyInstance(manager.getClass().getClassLoader(), types, (proxy, method, args) -> {
            switch (method.getName()) {
                case "getTransaction" -> enter(Objects.requireNonNullElse(
                        (TransactionDefinition) args[0], TransactionDefinition.withDefaults()));
                case "equals" -> {
                    return proxy == args[0];
                }
                case "hashCode" -> {
                    return System.identityHashCode(proxy);
                }
                default -> {}
            }
            try {
                return method.invoke(manager, args);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }
        });
    }
}
