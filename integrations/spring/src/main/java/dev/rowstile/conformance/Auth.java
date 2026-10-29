package dev.rowstile.conformance;

import dev.rowstile.Principal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Who a request is. A real app signs people in here: a session, a bearer token (oauth2ResourceServer), an API key.
 * The conformance app has no sign-in: its checks name the user in a header, which a real app must never believe. So
 * docs/stacks/spring.md shows the app's own Spring Security, and never this file.
 */
@Configuration
class Auth {
    @Bean
    SecurityFilterChain api(HttpSecurity http) {
        return http.csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a.anyRequest().permitAll())
                .addFilterBefore(new FromHeaders(), AnonymousAuthenticationFilter.class)
                .build();
    }

    /** The request's user (x-user), or a service (x-service: a service's own API calls). */
    static final class FromHeaders extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String service = request.getHeader("x-service");
            String user = request.getHeader("x-user");
            Principal who = service != null ? Principal.of("service", service) : user != null ? Principal.user(user) : null;
            if (who != null) {
                var auth = new PreAuthenticatedAuthenticationToken(who, "header", List.of());
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
            chain.doFilter(request, response);
        }
    }
}
