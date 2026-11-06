package dev.rowstile.conformance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.rowstile.Principal;
import dev.rowstile.Refused;
import dev.rowstile.Rowstile;
import java.sql.SQLException;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** The app with Hibernate's comments in its SQL (a common setting while debugging): the answers don't change. */
@SpringBootTest(properties = "spring.jpa.properties.hibernate.use_sql_comments=true")
class SqlCommentsTest extends Conformance {
    @Autowired
    Notes notes;

    @Autowired
    PlatformTransactionManager transactions;

    @BeforeEach
    void rows() throws SQLException {
        seed();
    }

    @Test
    @DisplayName("7: ... with comments in Hibernate's SQL, a refused delete is the delete rule's, a refused update the update rule's")
    void refusedWithComments() {
        TransactionTemplate tx = new TransactionTemplate(transactions);
        Refused delete = assertThrows(Refused.class, () -> Rowstile.actingAs(Principal.user(3), () -> tx.execute(s -> {
            notes.delete(notes.findById(1L).orElseThrow());
            return null;
        })));
        Refused update = assertThrows(Refused.class, () -> Rowstile.actingAs(Principal.user(3), () -> tx.execute(s -> {
            notes.findById(1L).orElseThrow().setBody("x");
            return null;
        })));
        assertEquals(List.of("delete", "permission denied: user 3 may not delete row 1 of app.notes", "update",
                "permission denied: user 3 may not update row 1 of app.notes"),
                List.of(delete.command(), delete.getMessage(), update.command(), update.getMessage()));
    }
}
