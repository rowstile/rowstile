package dev.rowstile.spring;

import dev.rowstile.Principal;
import dev.rowstile.Rowstile;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.aopalliance.intercept.MethodInterceptor;
import org.jspecify.annotations.Nullable;
import org.springframework.aop.framework.ProxyFactory;

/**
 * A connection of the app's {@link DataSource}, which knows whom its transaction signed in as. While a transaction
 * the starter signed in is open on it, each statement (a {@code JdbcClient}'s, JPA's, an {@code Authz} call's) is
 * refused before it is sent when the code acts for someone else, or for no one: an {@link IllegalStateException},
 * {@link Rowstile#signedInAlready}. The sign-in lasts until the transaction ends (a commit, a rollback, the
 * connection closed or back in auto-commit mode).
 */
final class SignedConnection implements InvocationHandler {
    /** What a connection of a data source the starter wraps is too: it can be told its transaction's sign-in. */
    interface Signed {
        /** Its transaction is signed in as {@code signed}; {@code who} says whom the code running now acts for. */
        void signedIn(Principal signed, Supplier<Principal> who);
    }

    private final Connection target;
    private @Nullable Principal signed;
    private Supplier<Principal> who = () -> Principal.NOBODY;

    private SignedConnection(Connection target) {
        this.target = target;
    }

    /**
     * {@code dataSource} itself, but for the connections it gives, which are {@link SignedConnection}s: a subclass of
     * its class, as Spring's own proxies are, so the app may still inject it by its class ({@code HikariDataSource});
     * a final class is stood in for by its interfaces.
     */
    static DataSource dataSource(DataSource dataSource) {
        ProxyFactory factory = new ProxyFactory(dataSource);
        factory.setProxyTargetClass(!Modifier.isFinal(dataSource.getClass().getModifiers()));
        factory.addAdvice((MethodInterceptor) call -> {
            Object result = call.proceed();
            return result instanceof Connection conn ? wrap(conn) : result;
        });
        return (DataSource) factory.getProxy(SignedConnection.class.getClassLoader());
    }

    private static Connection wrap(Connection target) {
        return (Connection) Proxy.newProxyInstance(SignedConnection.class.getClassLoader(),
                new Class<?>[] {Connection.class, Signed.class}, new SignedConnection(target));
    }

    @Override
    public @Nullable Object invoke(Object proxy, Method method, Object @Nullable [] args) throws Throwable {
        switch (method.getName()) {
            case "signedIn" -> {
                @SuppressWarnings("unchecked")
                Supplier<Principal> now = (Supplier<Principal>) args[1];
                signed = (Principal) args[0];
                who = now;
                return null;
            }
            case "createStatement", "prepareStatement", "prepareCall" -> {
                Principal now = signed == null ? null : who.get();
                if (now != null && !now.equals(signed)) {
                    throw Rowstile.signedInAlready(signed, now);
                }
            }
            // the transaction ends: a rollback to a savepoint doesn't end it (the sign-in is before any savepoint)
            case "commit", "close" -> signed = null;
            case "rollback" -> signed = args == null ? null : signed;
            case "setAutoCommit" -> signed = Boolean.TRUE.equals(args[0]) ? null : signed;
            case "equals" -> {
                return proxy == args[0];
            }
            case "hashCode" -> {
                return System.identityHashCode(proxy);
            }
            default -> {}
        }
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }
}
