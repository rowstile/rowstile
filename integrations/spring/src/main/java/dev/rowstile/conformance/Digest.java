package dev.rowstile.conformance;

import dev.rowstile.Principal;
import dev.rowstile.Rowstile;
import org.springframework.stereotype.Component;

/** A background job: it signs in as service 1, whatever request started it. */
@Component
public class Digest {
    /** What the job saw, and who it acted for. */
    public record Seen(long projects, Principal who) {}

    private final Projects projects;

    Digest(Projects projects) {
        this.projects = projects;
    }

    public Seen run() {
        return Rowstile.actingAs(Principal.of("service", 1), () ->
                new Seen(projects.count(), Rowstile.current().orElseThrow()));
    }
}
