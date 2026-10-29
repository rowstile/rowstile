package dev.rowstile.spring;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;

/**
 * Adds the sign-in to every {@link DataSourceTransactionManager} (and {@code JdbcTransactionManager}) of the app,
 * Spring Boot's or its own: each transaction they begin signs in first.
 */
class SignInTransactions implements BeanPostProcessor {
    private final ObjectProvider<PrincipalSource> source;

    SignInTransactions(ObjectProvider<PrincipalSource> source) {
        this.source = source;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        if (bean instanceof DataSourceTransactionManager manager) {
            manager.addListener(new SignIn(manager, manager::getDataSource, this::source));
        }
        return bean;
    }

    /** Who the request is: the app's {@link PrincipalSource}, Spring Security's, or nobody without either. */
    PrincipalSource source() {
        return source.getIfAvailable(() -> () -> dev.rowstile.Principal.NOBODY);
    }
}
