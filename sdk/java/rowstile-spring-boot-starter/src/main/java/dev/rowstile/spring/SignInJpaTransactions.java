package dev.rowstile.spring;

import dev.rowstile.Authz;
import java.util.function.Supplier;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.orm.jpa.JpaTransactionManager;

/**
 * Adds the sign-in to every {@link JpaTransactionManager} of the app, Spring Boot's or its own, on any JPA provider;
 * on Hibernate, it also asks why when a flush before the commit changed nothing. Work for someone else can't join a
 * transaction it began (the bean is the manager in a subclass of its class: inject it by its class or as a {@code
 * PlatformTransactionManager}). JDBC code inside those transactions ({@code JdbcClient}) runs on their connection,
 * signed in too.
 */
class SignInJpaTransactions implements BeanPostProcessor {
    private final SignInTransactions transactions;
    private final @Nullable Supplier<Authz> authz;

    /** {@code authz}: the runtime's calls, which say why a flush changed nothing; null without Hibernate. */
    SignInJpaTransactions(SignInTransactions transactions, @Nullable Supplier<Authz> authz) {
        this.transactions = transactions;
        this.authz = authz;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        if (bean instanceof JpaTransactionManager manager) {
            JpaSignIn signIn = authz == null
                    ? new JpaSignIn(manager, transactions::source)
                    : new HibernateSignIn(manager, transactions::source, authz);
            JpaTransactionManager guarded = signIn.guard(manager);
            guarded.addListener(signIn);
            return guarded;
        }
        return bean;
    }
}
