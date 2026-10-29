package dev.rowstile.conformance;

import dev.rowstile.NotFound;
import jakarta.persistence.EntityManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/** Routes only the checks have: an update the rules allow, that matches no row. */
@RestController
class TestRoutes {
    private final EntityManager em;

    TestRoutes(EntityManager em) {
        this.em = em;
    }

    @PatchMapping("/stubborn/{id}")
    @Transactional
    void stubborn(@PathVariable long id) {
        StubbornNote note = em.find(StubbornNote.class, id);
        if (note == null) {
            throw new NotFound("app.notes", id);
        }
        note.setBody("mine");
    }
}
