package dev.rowstile;

import java.util.Objects;

/**
 * Who a transaction acts for: a user (type {@code user}), another principal type the policy declares (a service, a
 * bot), or nobody (id {@code null}: only what {@code anyone} may see).
 *
 * <p>A plain id is a user's, whatever it holds: {@code Principal.user("service:3")} is the user whose id that is (ids
 * often come from outside: a username, an identity provider's subject), never service 3. Another principal type is
 * named: {@code Principal.of("service", 3)}.
 *
 * @param type the principal type, {@code user} for a user
 * @param id the id, or {@code null} for nobody
 */
public record Principal(String type, String id) {
    /** Nobody: only what {@code anyone} may see. */
    public static final Principal NOBODY = new Principal("user", null);

    public Principal {
        Objects.requireNonNull(type, "type");
    }

    /** The user whose id this is ({@code null}: nobody). */
    public static Principal user(Object id) {
        return id == null ? NOBODY : new Principal("user", id.toString());
    }

    /** A principal of the policy's type {@code type} ({@code service}, {@code bot}); {@code null} id: nobody. */
    public static Principal of(String type, Object id) {
        return id == null ? NOBODY : new Principal(type, id.toString());
    }

    /**
     * What {@link #toString()} wrote, read back: {@code service:3} is service 3, {@code 42} and {@code user:42} user
     * 42, {@code nobody} nobody. For text your own code wrote (a job's argument) and for who acted in the audit trail
     * (its user_id, a share's created_by), which the database writes the same way; not for an id that came from
     * outside.
     */
    public static Principal parse(String text) {
        if (text.equals("nobody")) {
            return NOBODY;
        }
        int colon = text.indexOf(':');
        if (colon >= 0 && !text.startsWith("(")) {
            return new Principal(text.substring(0, colon), text.substring(colon + 1));
        }
        return new Principal("user", text);
    }

    /** Whether this is nobody. */
    public boolean nobody() {
        return id == null;
    }

    /**
     * {@code 42}, {@code service:3} or {@code nobody}. A user whose id holds {@code :} or is {@code nobody} is
     * {@code user:<id>}, so that {@link #parse(String)} reads every principal back as itself.
     */
    @Override
    public String toString() {
        if (id == null) {
            return "nobody";
        }
        if (!type.equals("user")) {
            return type + ":" + id;
        }
        return id.contains(":") || id.equals("nobody") ? "user:" + id : id;
    }
}
