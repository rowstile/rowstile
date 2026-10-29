package dev.rowstile;

import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The runtime's {@code authz.*} functions, as whoever the transaction is signed in as. Over one connection, {@link
 * #on(Connection)}, inside a transaction signed in ({@link Rowstile#transaction}); the Spring starter has one over the
 * transaction Spring holds. The policy's names come from the generated file ({@code rowstile client java}), so a
 * misspelled type or permission doesn't compile. A database error is thrown as {@link DatabaseError}.
 */
public final class Authz {
    /** Where the calls run: on the connection of the transaction open now. */
    @FunctionalInterface
    public interface Connections {
        <T> T with(Rowstile.SqlWork<T> work) throws SQLException;
    }

    /**
     * What {@code authz.connection_check()} found.
     *
     * @param severity {@code error} for a connection the app must not start on, else {@code warning}
     * @param problem what is wrong, in the database's words
     */
    public record Finding(String severity, String problem) {}

    /**
     * What an UPDATE or DELETE that changed nothing was, asked of the database ({@code authz.explain_rule}).
     *
     * @param table the table as the policy names it, with its schema
     * @param command {@code update} or {@code delete}
     * @param key the row's key
     * @param why the rule's answer, a line each; {@code null} when the row isn't there for this user
     * @param who who is signed in, in the words the database's own refusals use ({@code user 2}, {@code service 3})
     */
    public record Verdict(String table, String command, Object key, List<String> why, String who) {
        /** Whether the rule allows the write: the statement matched nothing for another reason. */
        public boolean allowed() {
            return why != null && why.get(0).strip().startsWith("yes");
        }

        /**
         * The error to throw: {@link NotFound} when the row isn't there for this user, or when the rule allows the
         * write (a WHERE with more than the key); {@link Refused}, with why, otherwise, worded as the database words a
         * refused insert: {@code permission denied: user 2 may not update row 7 of app.notes}.
         */
        public RuntimeException error() {
            if (why == null || allowed()) {
                return new NotFound(table, key);
            }
            String message = "permission denied: " + who + " may not " + command + " row " + Keys.text(key) + " of "
                    + table;
            return new Refused(message, table, command, why, null, null);
        }
    }

    // The policy names tables with their schema; a table named without one is looked up on the search_path. In a
    // second column who is signed in, in the words the database's own refusals use, in a third the table's name
    private static final String VERDICT = "SELECT authz.explain_rule(t.tbl, ?, ?, NULL), coalesce((SELECT"
            + " p.principal_type || ' ' || p.principal_id FROM authz.principal() p), 'someone not signed in'), t.tbl"
            + " FROM (SELECT coalesce((SELECT n.nspname || '.' || c.relname FROM pg_catalog.pg_class c JOIN"
            + " pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE position('.' in a.name) = 0 AND c.oid ="
            + " pg_catalog.to_regclass(pg_catalog.quote_ident(a.name))), a.name) AS tbl FROM (SELECT CAST(? AS text)"
            + " AS name) a) t";

    private final Connections connections;

    private Authz(Connections connections) {
        this.connections = connections;
    }

    /** The calls on {@code conn}, in the transaction open on it. */
    public static Authz on(Connection conn) {
        return new Authz(new Connections() {
            @Override
            public <T> T with(Rowstile.SqlWork<T> work) throws SQLException {
                return work.run(conn);
            }
        });
    }

    /** The calls on the connections {@code connections} gives: the Spring starter's, over its transactions. */
    public static Authz over(Connections connections) {
        return new Authz(connections);
    }

    private <T> T run(Rowstile.SqlWork<T> work) {
        try {
            return connections.with(work);
        } catch (SQLException e) {
            throw new DatabaseError(e);
        }
    }

    /** Whether the user holds {@code perm} on the object {@code id}: {@code authz.can}. */
    public boolean can(Permission perm, Object id) {
        return run(c -> {
            try (PreparedStatement st = c.prepareStatement("SELECT authz.can(?, ?, ?)")) {
                st.setString(1, perm.type());
                st.setString(2, Keys.text(id));
                st.setString(3, perm.permission());
                try (ResultSet rs = st.executeQuery()) {
                    rs.next();
                    return rs.getBoolean(1);
                }
            }
        });
    }

    /** Every permission the user holds on the object {@code id}: {@code authz.perms}. */
    public <P extends Permission> List<P> perms(ObjectType<P> type, Object id) {
        return run(c -> {
            try (PreparedStatement st = c.prepareStatement("SELECT authz.perms(?, ?)")) {
                st.setString(1, type.name());
                st.setString(2, Keys.text(id));
                try (ResultSet rs = st.executeQuery()) {
                    rs.next();
                    return permissions(type, rs.getArray(1));
                }
            }
        });
    }

    /** The permissions the user holds on each of many objects, by id: a list's buttons in one call. */
    public <P extends Permission> Map<String, List<P>> permsOf(ObjectType<P> type, Collection<?> ids) {
        return run(c -> {
            try (PreparedStatement st = c.prepareStatement("SELECT id, perms FROM authz.perms_of(?, ?)")) {
                st.setString(1, type.name());
                st.setArray(2, c.createArrayOf("text", ids.stream().map(Keys::text).toArray()));
                Map<String, List<P>> out = new LinkedHashMap<>();
                try (ResultSet rs = st.executeQuery()) {
                    while (rs.next()) {
                        out.put(rs.getString(1), permissions(type, rs.getArray(2)));
                    }
                }
                return out;
            }
        });
    }

    private static <P extends Permission> List<P> permissions(ObjectType<P> type, Array names) throws SQLException {
        List<P> out = new ArrayList<>();
        for (Object name : (Object[]) names.getArray()) {
            out.add(type.permission((String) name));
        }
        return out;
    }

    /** The ids of the objects the user holds {@code perm} on, in key order: {@code authz.list}. */
    public List<String> list(Permission perm) {
        return list(perm, null, null);
    }

    /**
     * A page of them: those after the id {@code after} ({@code null}: from the first), at most {@code limit}
     * ({@code null}: no limit). The database says when the cursor or the size is wrong (AZ710).
     */
    public List<String> list(Permission perm, Object after, Integer limit) {
        return run(c -> {
            try (PreparedStatement st = c.prepareStatement("SELECT x FROM authz.list(?, ?, ?, ?) x")) {
                st.setString(1, perm.type());
                st.setString(2, perm.permission());
                st.setString(3, Keys.text(after));
                st.setObject(4, limit, Types.INTEGER);
                List<String> ids = new ArrayList<>();
                try (ResultSet rs = st.executeQuery()) {
                    while (rs.next()) {
                        ids.add(rs.getString(1));
                    }
                }
                return ids;
            }
        });
    }

    /**
     * What an UPDATE or DELETE of the row {@code key} of {@code table} that changed nothing was, asked of the database
     * in the same transaction. {@code key}: the row's key, a {@link List} of its values for a key of several columns.
     */
    public Verdict verdict(String table, String command, Object key) {
        return run(c -> {
            try (PreparedStatement st = c.prepareStatement(VERDICT)) {
                st.setString(1, command);
                st.setString(2, Keys.text(key));
                st.setString(3, table);
                try (ResultSet rs = st.executeQuery()) {
                    rs.next();
                    Array lines = rs.getArray(1);
                    List<String> why = lines == null ? null : List.of((String[]) lines.getArray());
                    return new Verdict(rs.getString(3), command, key, why, rs.getString(2));
                }
            }
        });
    }

    /**
     * An UPDATE or DELETE's row count, returned if it changed something; else {@link NotFound} (the row is hidden, or
     * didn't match) or {@link Refused} (the user may not, and why), asked of the database in the same transaction.
     * Row-level security skips the rows a user may not change without an error.
     */
    public int expect(int changed, String table, String command, Object key) {
        if (changed > 0) {
            return changed;
        }
        throw verdict(table, command, key).error();
    }

    /** What {@code authz.connection_check()} finds wrong with this connection. */
    public List<Finding> connectionCheck() {
        return run(c -> {
            List<Finding> out = new ArrayList<>();
            try (PreparedStatement st = c.prepareStatement("SELECT severity, problem FROM authz.connection_check()");
                    ResultSet rs = st.executeQuery()) {
                while (rs.next()) {
                    out.add(new Finding(rs.getString(1), rs.getString(2)));
                }
            }
            return out;
        });
    }

    /**
     * Throws {@link ConnectionProblem} if this connection skips row-level security (a superuser, BYPASSRLS, the
     * tables' owner), where the database would filter nothing: at start-up, before serving.
     */
    public void check() {
        List<String> errors = connectionCheck().stream()
                .filter(f -> f.severity().equals("error"))
                .map(Finding::problem)
                .toList();
        if (!errors.isEmpty()) {
            throw new ConnectionProblem(errors);
        }
    }
}
