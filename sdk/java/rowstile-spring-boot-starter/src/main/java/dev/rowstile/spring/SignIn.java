package dev.rowstile.spring;

import dev.rowstile.Principal;
import dev.rowstile.Rowstile;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionExecution;
import org.springframework.transaction.TransactionExecutionListener;
import org.springframework.transaction.TransactionStatus;

/**
 * Signs each transaction a transaction manager begins in, as its first statement: as whoever the code acts for
 * ({@link Rowstile#actingAs}, a job), else whoever the request is ({@link PrincipalSource}), else nobody. The sign-in
 * lasts the transaction: a pooled connection carries no one into the next. A savepoint (a nested transaction) keeps
 * the transaction's.
 */
class SignIn implements TransactionExecutionListener {
    private final PlatformTransactionManager manager;
    private final Supplier<DataSource> dataSource;
    private final Supplier<PrincipalSource> source;

    SignIn(PlatformTransactionManager manager, Supplier<DataSource> dataSource, Supplier<PrincipalSource> source) {
        this.manager = manager;
        this.dataSource = dataSource;
        this.source = source;
    }

    @Override
    public void afterBegin(TransactionExecution transaction, @Nullable Throwable beginFailure) {
        if (beginFailure != null || !transaction.isNewTransaction()) {
            return;
        }
        Principal who = Rowstile.current().orElseGet(() -> source.get().principal());
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
    }
}
