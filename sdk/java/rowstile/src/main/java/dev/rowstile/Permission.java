package dev.rowstile;

/**
 * A permission of a type the policy declares: {@code edit} on {@code note}. The generated names ({@code rowstile
 * client java}) are an enum of each type's, so a misspelled type or permission doesn't compile:
 * {@code authz.can(NotePermission.EDIT, 7)}.
 */
public interface Permission {
    /** The type's name, as the policy writes it ({@code note}). */
    String type();

    /** The permission's name, as the policy writes it ({@code edit}). */
    String permission();

    /** A permission by its names, for code without the generated ones: nothing checks them before the database. */
    static Permission of(String type, String permission) {
        return new Named(type, permission);
    }

    /**
     * A permission by its names.
     *
     * @param type the type's name
     * @param permission the permission's name
     */
    record Named(String type, String permission) implements Permission {}
}
