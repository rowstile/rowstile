package dev.rowstile.spring;

import dev.rowstile.Principal;
import dev.rowstile.Rowstile;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.jspecify.annotations.Nullable;
import org.springframework.cglib.core.ClassLoaderAwareGeneratorStrategy;
import org.springframework.cglib.core.SpringNamingPolicy;
import org.springframework.cglib.proxy.Callback;
import org.springframework.cglib.proxy.CallbackFilter;
import org.springframework.cglib.proxy.Enhancer;
import org.springframework.cglib.proxy.Factory;
import org.springframework.cglib.proxy.MethodInterceptor;
import org.springframework.cglib.proxy.NoOp;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.objenesis.SpringObjenesis;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.TransactionExecution;
import org.springframework.transaction.TransactionExecutionListener;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.transaction.support.ResourceTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.ReflectionUtils;

/**
 * Signs each transaction a transaction manager begins in, as its first statement: as whoever the code acts for
 * ({@link Rowstile#actingAs}, a job), else whoever the request is ({@link PrincipalSource}), else nobody. The sign-in
 * lasts the transaction: a pooled connection carries no one into the next.
 *
 * <p>A transaction is one principal's. Work that joins the transaction open now (a {@code @Transactional} method, a
 * {@code TransactionTemplate}, a repository's call, a savepoint: {@code NESTED}) runs as it is when the code acts for
 * the principal it signed in as; for anyone else, it is refused before anything is sent for it (an {@link
 * IllegalStateException}), and the transaction is left as it was. So is a statement on its connection while the code
 * acts for someone else ({@link SignedConnection}). A transaction of its own ({@code REQUIRES_NEW}, another
 * connection) signs in as whoever it is for.
 */
class SignIn implements TransactionExecutionListener {
    /** Whom each open transaction signed in as, by the resource it holds (its connection's, its entity manager's). */
    private static final Map<Object, Principal> SIGNED = Collections.synchronizedMap(new WeakHashMap<>());

    /** Of a transaction manager's methods, the one that sees work join a transaction (1), and the others (0). */
    private static final CallbackFilter JOINING = method -> method.getName().equals("prepareSynchronization") ? 1 : 0;

    private static final SpringObjenesis OBJENESIS = new SpringObjenesis();

    private ResourceTransactionManager manager;
    private final Supplier<PrincipalSource> source;

    SignIn(ResourceTransactionManager manager, Supplier<PrincipalSource> source) {
        this.manager = manager;
        this.source = source;
    }

    /** The manager this signs in for. */
    ResourceTransactionManager manager() {
        return manager;
    }

    /** Whom the code running now acts for. */
    private Principal who() {
        return Rowstile.current().orElseGet(() -> source.get().principal());
    }

    @Override
    public void beforeBegin(TransactionExecution transaction) {
        if (!transaction.isNewTransaction()) {
            enter(); // a savepoint (NESTED) of the transaction open now
        }
    }

    @Override
    public void afterBegin(TransactionExecution transaction, @Nullable Throwable beginFailure) {
        if (beginFailure != null || !transaction.isNewTransaction()) {
            return;
        }
        Principal who = who();
        DataSource ds = dataSource();
        Connection conn = DataSourceUtils.getConnection(ds);
        SQLException refused = null;
        try {
            Rowstile.signIn(conn, who);
            if (conn instanceof SignedConnection.Signed signed) {
                signed.signedIn(who, this::who);
            }
        } catch (SQLException e) {
            refused = e;
        } finally {
            DataSourceUtils.releaseConnection(conn, ds);
        }
        if (refused != null) {
            // begun, and not signed in: ended here, so that nothing is left bound to the thread
            ((AbstractPlatformTransactionManager) manager).rollback((TransactionStatus) transaction);
            throw new CannotCreateTransactionException("the transaction could not be signed in (authz.act_as)", refused);
        }
        SIGNED.put(TransactionSynchronizationManager.getResource(manager.getResourceFactory()), who);
    }

    /** The data source the manager's transactions are on. */
    DataSource dataSource() {
        return ((DataSourceTransactionManager) manager).getDataSource();
    }

    /**
     * Before work joins the transaction open now (or begins a savepoint of it): refused if that transaction is signed
     * in as someone else than whoever the code acts for.
     */
    void enter() {
        Principal who = who();
        Object held = TransactionSynchronizationManager.getResource(manager.getResourceFactory());
        Principal signed = SIGNED.getOrDefault(held, who);
        if (!signed.equals(who)) {
            throw Rowstile.signedInAlready(signed, who);
        }
    }

    /**
     * The transaction manager the app's code gets: {@code manager} in a subclass of its class, holding what it holds,
     * whose work that joins a transaction first asks {@link #enter} (Spring calls no listener then, and its {@code
     * getTransaction} is final: no stand-in in front of it would see the call). The app may inject it by its class
     * ({@code JpaTransactionManager}) or as a {@code PlatformTransactionManager}. A final class is left as it is: work
     * that joins one of its transactions for someone else is refused at its first statement instead.
     */
    <M extends AbstractPlatformTransactionManager & ResourceTransactionManager> M guard(M manager) {
        Class<?> type = manager.getClass();
        if (Modifier.isFinal(type.getModifiers())) {
            return manager;
        }
        Enhancer enhancer = new Enhancer();
        enhancer.setSuperclass(type);
        enhancer.setNamingPolicy(SpringNamingPolicy.INSTANCE);
        enhancer.setStrategy(new ClassLoaderAwareGeneratorStrategy(type.getClassLoader()));
        enhancer.setCallbackFilter(JOINING);
        enhancer.setCallbackTypes(new Class<?>[] {NoOp.class, MethodInterceptor.class});
        @SuppressWarnings("unchecked")
        M guarded = (M) OBJENESIS.newInstance(enhancer.createClass());
        ((Factory) guarded).setCallbacks(new Callback[] {NoOp.INSTANCE, (MethodInterceptor) (self, method, args, proxy) -> {
            // a status for work that joins a transaction open now: neither new, nor without a transaction
            DefaultTransactionStatus status = (DefaultTransactionStatus) args[0];
            if (status.hasTransaction() && !status.isNewTransaction()) {
                enter();
            }
            return proxy.invokeSuper(self, args);
        }});
        // what the manager holds, the same objects (its data source, its entity manager factory, its listeners)
        ReflectionUtils.doWithFields(type, field -> copy(field, manager, guarded),
                field -> !Modifier.isStatic(field.getModifiers()));
        this.manager = guarded;
        return guarded;
    }

    private static void copy(Field field, Object from, Object to) throws IllegalAccessException {
        field.setAccessible(true);
        field.set(to, field.get(from));
    }
}
