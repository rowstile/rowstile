package dev.rowstile.spring;

import dev.rowstile.Principal;

/**
 * Who the request is: asked as each transaction begins, unless the code acts for someone already ({@link
 * dev.rowstile.Rowstile#actingAs}, a job). With Spring Security the starter has one: the signed-in principal's name
 * is the user's id, or the {@link Principal} itself when the authentication holds one. Declare a bean of your own for
 * another (a session's user, read from the request).
 */
@FunctionalInterface
public interface PrincipalSource {
    /** Who the request is; {@link Principal#NOBODY} for a visitor who isn't signed in. */
    Principal principal();
}
