package dev.rowstile;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An RFC 9457 problem body: what an HTTP API answers for a refusal (403), a row that isn't there (404), or another
 * call the database turned down (401, 400, 409). The types are pages of rowstile.dev:
 * {@code https://rowstile.dev/problems/refused}, {@code /not-found}, {@code /not-signed-in}, {@code /bad-argument},
 * {@code /conflict}.
 *
 * @param type the problem's type, a URI
 * @param title the status's words ({@code Forbidden})
 * @param status the HTTP status
 * @param detail the database's words: for a refusal, who may not do what, where
 * @param members the problem's own members, in order: a refusal's {@code table}, {@code command}, {@code why} (a line
 *     each) and {@code code}; another's {@code code} (rowstile's, {@code rowstile help AZ710}). A member may be null
 */
public record Problem(String type, String title, int status, String detail, Map<String, Object> members) {
    static final String PAGES = "https://rowstile.dev/problems/";

    public Problem {
        members = Collections.unmodifiableMap(new LinkedHashMap<>(members));
    }
}
