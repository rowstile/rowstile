package dev.rowstile.spring;

import java.util.function.Supplier;
import javax.sql.DataSource;
import org.springframework.orm.jpa.JpaTransactionManager;

/**
 * The sign-in for JPA's transactions, on any JPA provider: on the connection the transaction holds, which a {@link
 * JpaTransactionManager} binds for its data source ({@link HibernateSignIn} also says why a flush changed nothing).
 */
class JpaSignIn extends SignIn {
    JpaSignIn(JpaTransactionManager manager, Supplier<PrincipalSource> source) {
        super(manager, source);
    }

    JpaTransactionManager jpa() {
        return (JpaTransactionManager) manager();
    }

    @Override
    DataSource dataSource() {
        return jpa().getDataSource();
    }
}
