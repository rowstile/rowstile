package dev.rowstile.spring;

import dev.rowstile.Authz;
import jakarta.persistence.EntityManagerFactory;
import java.sql.Connection;
import javax.sql.DataSource;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.DispatcherServlet;

/**
 * rowstile for Spring Boot: every transaction Spring begins (JDBC's and JPA's transaction managers, {@code
 * @Transactional}, {@code TransactionTemplate}) signs in first, as the request's user, and work for someone else
 * can't join it (an {@link IllegalStateException}); refusals answer as problem details; and the app doesn't start on a
 * connection that skips row-level security ({@code rowstile.check-connection}, on unless set to false).
 */
@AutoConfiguration(
        afterName = {
            "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
            "org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration"
        })
public class RowstileAutoConfiguration {
    /** The sign-in, added to each JDBC transaction manager. */
    @Bean
    static SignInTransactions rowstileSignIn(ObjectProvider<PrincipalSource> source) {
        return new SignInTransactions(source);
    }

    /**
     * The runtime's calls, in the transaction open now (as its user, seeing what it wrote): {@code authz.can(...)},
     * {@code authz.expect(...)}. Outside a transaction a call is in one of its own, signed in to nobody's name: it
     * fails as any query would there (AZ701).
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(DataSource.class)
    public Authz rowstileAuthz(DataSource dataSource) {
        return Authz.over(new Authz.Connections() {
            @Override
            public <T> T with(dev.rowstile.Rowstile.SqlWork<T> work) throws java.sql.SQLException {
                Connection conn = DataSourceUtils.getConnection(dataSource);
                try {
                    return work.run(conn);
                } finally {
                    DataSourceUtils.releaseConnection(conn, dataSource);
                }
            }
        });
    }

    /** The check at start-up. */
    @Bean
    @ConditionalOnBean(DataSource.class)
    @ConditionalOnProperty(name = "rowstile.check-connection", havingValue = "true", matchIfMissing = true)
    ConnectionCheck rowstileConnectionCheck(DataSource dataSource) {
        return new ConnectionCheck(dataSource);
    }

    /** Who the request is, from Spring Security, unless the app says otherwise. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(SecurityContextHolder.class)
    static class Security {
        @Bean
        @ConditionalOnMissingBean
        PrincipalSource rowstilePrincipalSource() {
            return new SecurityPrincipalSource();
        }
    }

    /** JPA's transactions: signed in, and why a flush changed nothing. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass({JpaTransactionManager.class, EntityManagerFactory.class, org.hibernate.Session.class})
    static class Jpa {
        @Bean
        static SignInJpaTransactions rowstileJpaSignIn(SignInTransactions transactions, ObjectProvider<Authz> authz) {
            return new SignInJpaTransactions(transactions, authz);
        }
    }

    /** Problem details, in a Spring MVC app. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnClass(DispatcherServlet.class)
    static class Web {
        @Bean
        Problems rowstileProblems() {
            return new Problems();
        }
    }
}
