package dev.rowstile;

import java.io.Serial;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The database refused a write, and said why: the rule (its table and command), and the explanation, a line each. A
 * 403. Its code is rowstile's ({@code rowstile help AZ709}): AZ709 for a rule's refusal, the database's own for
 * another (AZ705: a share).
 */
public final class Refused extends RuntimeException {
    @Serial
    private static final long serialVersionUID = 1L;

    private final String table;
    private final String command;
    private final String[] why; // (an array: what an exception holds is serializable)
    private final String code;

    public Refused(String message, String table, String command, List<String> why, String code, Throwable cause) {
        super(message, cause);
        this.table = table;
        this.command = command;
        this.why = why.toArray(String[]::new);
        this.code = code == null ? "AZ709" : code;
    }

    /** The table, with its schema ({@code app.notes}), when the error names it. */
    public String table() {
        return table;
    }

    /** The rule's command: {@code insert}, {@code update}, {@code delete} or {@code select}, when the error names it. */
    public String command() {
        return command;
    }

    /** Why: the rule, then what holds and what is missing, a line each. */
    public List<String> why() {
        return List.of(why);
    }

    /** rowstile's code: AZ709 for a rule's refusal. */
    public String code() {
        return code;
    }

    /** The problem body for a 403. */
    public Problem problem() {
        Map<String, Object> members = new LinkedHashMap<>();
        members.put("table", table);
        members.put("command", command);
        members.put("why", why());
        members.put("code", code);
        return new Problem(Problem.PAGES + "refused", "Forbidden", 403, getMessage(), members);
    }
}
