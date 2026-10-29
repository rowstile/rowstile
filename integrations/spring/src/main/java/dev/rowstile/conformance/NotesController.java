package dev.rowstile.conformance;

import dev.rowstile.Authz;
import dev.rowstile.NotFound;
import dev.rowstile.spring.PrincipalSource;
import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Notes, the inbox and folders: JPA's repositories, and JdbcClient beside them, in the same transactions. */
@RestController
class NotesController {
    private final Notes notes;
    private final Inbox inbox;
    private final Folders folders;
    private final JdbcClient jdbc;
    private final Authz calls;
    private final PrincipalSource me;
    private final EntityManager em;

    NotesController(Notes notes, Inbox inbox, Folders folders, JdbcClient jdbc, Authz calls, PrincipalSource me,
            EntityManager em) {
        this.notes = notes;
        this.inbox = inbox;
        this.folders = folders;
        this.jdbc = jdbc;
        this.calls = calls;
        this.me = me;
        this.em = em;
    }

    /** The user the request is, as the tables' key (0: nobody). */
    private long signedIn() {
        String id = me.principal().id();
        return id == null ? 0 : Long.parseLong(id);
    }

    @GetMapping("/notes")
    List<Long> list() {
        return notes.findAll().stream().map(Note::getId).sorted().toList();
    }

    record NewNote(long projectId, String body) {}

    @PostMapping("/notes")
    @ResponseStatus(HttpStatus.CREATED)
    Map<String, Long> add(@RequestBody NewNote n) {
        return Map.of("id", notes.save(new Note(n.projectId(), signedIn(), n.body())).getId());
    }

    record Body(String body) {}

    @PatchMapping("/notes/{id}")
    @Transactional
    Map<String, Long> edit(@PathVariable long id, @RequestBody Body b) {
        Note note = notes.findById(id).orElseThrow(() -> new NotFound("app.notes", id));
        note.setBody(b.body()); // an update the rules may refuse: 403 with the reason, at the commit
        return Map.of("id", id);
    }

    @DeleteMapping("/notes/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    void remove(@PathVariable long id) {
        int deleted = jdbc.sql("DELETE FROM app.notes WHERE id = ?").param(id).update();
        calls.expect(deleted, "app.notes", "delete", id); // 0 rows: 404, or 403 with the reason
    }

    @GetMapping("/notes/as/{user}")
    @Transactional(readOnly = true)
    List<?> notesAs(@PathVariable long user) {
        // who is signed in, changed by hand: the database doesn't believe it (the app's bug, a 500)
        em.createNativeQuery("SELECT set_config('authz.user_id', CAST(?1 AS text), true)")
                .setParameter(1, user)
                .getSingleResult();
        return em.createNativeQuery("SELECT id FROM app.notes ORDER BY id").getResultList();
    }

    record NewMessage(long recipientId, String body) {}

    @PostMapping("/inbox")
    @ResponseStatus(HttpStatus.CREATED)
    Map<String, Long> send(@RequestBody NewMessage m) {
        // the new id is read back (RETURNING): only the recipient may read the row
        return Map.of("id", inbox.save(new Message(signedIn(), m.recipientId(), m.body())).getId());
    }

    @PostMapping("/inbox/quietly")
    @ResponseStatus(HttpStatus.ACCEPTED)
    @Transactional
    Map<String, Long> sendQuietly(@RequestBody NewMessage m) {
        // without reading the row back
        jdbc.sql("INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES (?, ?, ?)")
                .params(signedIn(), m.recipientId(), m.body())
                .update();
        return Map.of();
    }

    record Move(Long parentId) {}

    @PatchMapping("/folders/{id}")
    @Transactional
    Map<String, Long> move(@PathVariable long id, @RequestBody Move m) {
        Folder folder = folders.findById(id).orElseThrow(() -> new NotFound("app.folders", id));
        folder.setParentId(m.parentId()); // inside one of its own subfolders: 409, the database's words
        return Map.of("id", id);
    }
}
