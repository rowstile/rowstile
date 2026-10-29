package dev.rowstile;

import java.io.Serial;
import java.sql.SQLException;

/**
 * A database error from one of this SDK's calls, unchecked: its cause is the driver's {@link SQLException}. {@link
 * Errors#problem(Throwable)} reads it as any other.
 */
public final class DatabaseError extends RuntimeException {
    @Serial
    private static final long serialVersionUID = 1L;

    public DatabaseError(SQLException cause) {
        super(cause.getMessage(), cause);
    }

    /** The driver's error. */
    @Override
    public synchronized SQLException getCause() {
        return (SQLException) super.getCause();
    }
}
