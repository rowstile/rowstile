package dev.rowstile.spring;

import dev.rowstile.Principal;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * The request's user from Spring Security: nobody when no one is signed in (no authentication, or an anonymous one);
 * the {@link Principal} the authentication holds, if it holds one (a service); else the user whose id is its name.
 */
final class SecurityPrincipalSource implements PrincipalSource {
    @Override
    public Principal principal() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth instanceof AnonymousAuthenticationToken || !auth.isAuthenticated()) {
            return Principal.NOBODY;
        }
        return auth.getPrincipal() instanceof Principal p ? p : Principal.user(auth.getName());
    }
}
