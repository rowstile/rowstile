package dev.rowstile.spring;

import dev.rowstile.Authz;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.orm.jpa.JpaTransactionManager;

/**
 * Adds the sign-in to every {@link JpaTransactionManager} of the app, Spring Boot's or its own, and asks why when a
 * flush before the commit changed nothing; work for someone else can't join a transaction it began (the bean is the
 * manager in a subclass of its class: inject it by its class or as a {@code PlatformTransactionManager}). JDBC code
 * inside those transactions ({@code JdbcClient}) runs on their connection, signed in too.
 */
class SignInJpaTransactions implements BeanPostProcessor {
    private final SignInTransactions transactions;
    private final ObjectProvider<Authz> authz;

    SignInJpaTransactions(SignInTransactions transactions, ObjectProvider<Authz> authz) {
        this.transactions = transactions;
        this.authz = authz;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        if (bean instanceof JpaTransactionManager manager) {
            JpaSignIn signIn = new JpaSignIn(manager, transactions::source, authz::getObject);
            JpaTransactionManager guarded = signIn.guard(manager);
            guarded.addListener(signIn);
            return guarded;
        }
        return bean;
    }
}
