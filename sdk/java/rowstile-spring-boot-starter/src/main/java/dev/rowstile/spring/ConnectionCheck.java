package dev.rowstile.spring;

import dev.rowstile.Authz;
import dev.rowstile.DatabaseError;
import java.sql.Connection;
import java.sql.SQLException;
import javax.sql.DataSource;
import org.springframework.beans.factory.SmartInitializingSingleton;

/**
 * At start-up, once every bean is made (the migrations have run) and before the app serves anything: the app's
 * connection must not skip row-level security (a superuser, BYPASSRLS, the tables' owner), where the database would
 * filter nothing. On one that does the app doesn't start: {@link dev.rowstile.ConnectionProblem} says why.
 */
final class ConnectionCheck implements SmartInitializingSingleton {
    private final DataSource dataSource;

    ConnectionCheck(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public void afterSingletonsInstantiated() {
        try (Connection conn = dataSource.getConnection()) {
            Authz.on(conn).check();
        } catch (SQLException e) {
            throw new DatabaseError(e);
        }
    }
}
