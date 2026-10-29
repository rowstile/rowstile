package dev.rowstile;

import java.util.function.Function;

/**
 * A type the policy declares, with the type of its permissions: what {@link Authz#perms} and {@link Authz#permsOf}
 * answer in. The generated names ({@code rowstile client java}) have one for each type:
 * {@code ObjectType.of("note", NotePermission.class)}.
 *
 * @param <P> the type's permissions
 */
public final class ObjectType<P extends Permission> {
    private final String name;
    private final Function<String, P> permission;

    private ObjectType(String name, Function<String, P> permission) {
        this.name = name;
        this.permission = permission;
    }

    /** The type {@code name}, whose permissions are the constants of {@code permissions}. */
    public static <E extends Enum<E> & Permission> ObjectType<E> of(String name, Class<E> permissions) {
        return new ObjectType<>(name, text -> {
            for (E p : permissions.getEnumConstants()) {
                if (p.permission().equals(text)) {
                    return p;
                }
            }
            throw new IllegalStateException(name + " has a permission " + text + " in the policy in force that "
                    + permissions.getSimpleName() + " doesn't: write the names again (rowstile client)");
        });
    }

    /** The type {@code name}, for code without the generated names: its permissions are read as they come. */
    public static ObjectType<Permission> of(String name) {
        return new ObjectType<>(name, text -> Permission.of(name, text));
    }

    /** The type's name, as the policy writes it. */
    public String name() {
        return name;
    }

    P permission(String text) {
        return permission.apply(text);
    }
}
