package dev.rowstile.conformance;

import static dev.rowstile.conformance.AuthzNames.PROJECT;

import dev.rowstile.Authz;
import dev.rowstile.Permission;
import dev.rowstile.conformance.AuthzNames.ProjectPermission;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Projects, by permission, and the runtime's calls in SQL: API keys, shares, access requests. */
@RestController
class ProjectsController {
    private final Projects projects;
    private final JdbcClient jdbc;
    private final Authz calls;

    ProjectsController(Projects projects, JdbcClient jdbc, Authz calls) {
        this.projects = projects;
        this.jdbc = jdbc;
        this.calls = calls;
    }

    @GetMapping("/projects")
    List<Long> list() {
        return projects.findAll().stream().map(Project::getId).sorted().toList();
    }

    @GetMapping("/projects/editable")
    @Transactional(readOnly = true)
    List<Long> editable() {
        return calls.list(ProjectPermission.EDIT).stream().map(Long::valueOf).toList();
    }

    @GetMapping("/projects/buttons")
    @Transactional(readOnly = true)
    Map<String, List<String>> buttons() {
        List<Long> ids = projects.findAll().stream().map(Project::getId).toList();
        Map<String, List<String>> out = new LinkedHashMap<>();
        calls.permsOf(PROJECT, ids).forEach((id, perms) -> out.put(id, perms.stream().map(Permission::permission).toList()));
        return out;
    }

    @GetMapping("/projects/page")
    @Transactional(readOnly = true)
    List<String> page(@RequestParam int limit, @RequestParam(required = false) String after) {
        // the projects the user may see, a page at a time: the database says when the size or the cursor is wrong
        return calls.list(ProjectPermission.VIEW, after, limit);
    }

    @DeleteMapping("/keys/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    void revokeKey(@PathVariable long id) {
        // one of the user's API keys: someone else's, or one that isn't there, is 404
        jdbc.sql("SELECT 1 FROM authz.revoke_api_key(?)").param(id).query(Integer.class).single();
    }

    record NewKey(String name, String principalType, String principalId) {}

    @PostMapping("/keys")
    @ResponseStatus(HttpStatus.CREATED)
    @Transactional
    Map<String, String> createKey(@RequestBody NewKey k, @RequestHeader(name = "x-api-key", required = false) String key) {
        // an API key, for the user or a principal whose keys they manage; a request that brings a key (x-api-key)
        // signs in with it first, in the same transaction: the database says who may make which
        if (key != null) {
            jdbc.sql("SELECT 1 FROM authz.login_key(?)").param(key).query(Integer.class).single();
        }
        String made = jdbc.sql("SELECT authz.create_api_key(?, '', NULL, CAST(? AS text), CAST(? AS text))")
                .params(k.name(), k.principalType(), k.principalId())
                .query(String.class)
                .single();
        return Map.of("key", made);
    }

    @GetMapping("/projects/{id}/shares")
    @Transactional(readOnly = true)
    List<String> shares(@PathVariable long id) {
        return jdbc.sql("SELECT subject_id FROM authz.list_shares('project', CAST(? AS text))")
                .param(id)
                .query(String.class)
                .list();
    }

    record Ask(String relation, String reason) {}

    @PostMapping("/projects/{id}/requests")
    @ResponseStatus(HttpStatus.CREATED)
    @Transactional
    Map<String, Long> ask(@PathVariable long id, @RequestBody Ask a) {
        // access asked for: the policy shares no relation of a project, so this is the app's mistake (a 500), once
        // the database knows who asks
        long made = jdbc.sql("SELECT authz.request_access('project', CAST(? AS text), ?, ?)")
                .params(id, a.relation(), a.reason())
                .query(Long.class)
                .single();
        return Map.of("id", made);
    }
}
