package dev.rowstile.spring;

import javax.sql.DataSource;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;

/**
 * Adds the sign-in to every {@link DataSourceTransactionManager} (and {@code JdbcTransactionManager}) of the app,
 * Spring Boot's or its own: each transaction they begin signs in first, and work for someone else can't join one
 * (the bean is the manager in a subclass of its class: inject it by its class or as a {@code
 * PlatformTransactionManager}). Every {@link DataSource} of the app gives connections that refuse a statement for
 * someone else inside a transaction signed in ({@link SignedConnection}).
 */
class SignInTransactions implements BeanPostProcessor {
    private final ObjectProvider<PrincipalSource> source;

    SignInTransactions(ObjectProvider<PrincipalSource> source) {
        this.source = source;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        if (bean instanceof DataSourceTransactionManager manager) {
            SignIn signIn = new SignIn(manager, this::source);
            DataSourceTransactionManager guarded = signIn.guard(manager);
            guarded.addListener(signIn);
            return guarded;
        }
        return bean instanceof DataSource dataSource ? SignedConnection.dataSource(dataSource) : bean;
    }

    /** Who the request is: the app's {@link PrincipalSource}, Spring Security's, or nobody without either. */
    PrincipalSource source() {
        return source.getIfAvailable(() -> () -> dev.rowstile.Principal.NOBODY);
    }
}
