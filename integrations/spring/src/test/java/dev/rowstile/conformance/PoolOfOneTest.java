package dev.rowstile.conformance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.rowstile.Errors;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;
import javax.sql.DataSource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

/** Check 4: the app with a pool of one connection (HikariCP's), which every request takes in turn. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.datasource.hikari.maximum-pool-size=1")
class PoolOfOneTest extends Conformance {
    @LocalServerPort
    int port;

    @Autowired
    DataSource pool;

    @Test
    @DisplayName("4: with a pool of one connection, a request as ann, then one as bo: bo never sees ann's rows")
    void poolOfOne() throws SQLException {
        seed();
        assertEquals(NOTES.get("1"), call(port, "GET", "/notes", "1", null).ids());
        assertEquals(NOTES.get("2"), call(port, "GET", "/notes", "2", null).ids());
        assertEquals(NOTES.get(""), call(port, "GET", "/notes", null, null).ids());
        // a transaction that commits (a folder moved where it is): a rollback undoes even a session's settings
        assertEquals(200, call(port, "PATCH", "/folders/2", "1", Map.of("parentId", 1)).status());
        // each request signed in again, so the answers alone can't tell: the pool's one connection, as the last
        // request left it, in a transaction nobody signs in to, holds no one (a sign-in that outlived its
        // transaction would still be ann's here)
        try (Connection conn = pool.getConnection(); Statement st = conn.createStatement()) {
            conn.setAutoCommit(false);
            try (ResultSet rs = st.executeQuery("SELECT current_setting('authz.user_id', true)")) {
                rs.next();
                String left = rs.getString(1);
                assertTrue(left == null || left.isEmpty(), left);
            }
            SQLException e = assertThrows(SQLException.class, () -> st.executeQuery("SELECT count(*) FROM app.notes"));
            assertEquals("AZ701", Errors.errorCode(e).orElseThrow()); // rowstile help AZ701
            conn.rollback();
        }
    }
}
