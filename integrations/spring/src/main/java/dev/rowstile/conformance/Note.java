package dev.rowstile.conformance;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** A note in a project. */
@Entity
@Table(schema = "app", name = "notes")
public class Note {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "project_id")
    private long projectId;

    @Column(name = "author_id")
    private long authorId;

    private String body;

    protected Note() {}

    public Note(long projectId, long authorId, String body) {
        this.projectId = projectId;
        this.authorId = authorId;
        this.body = body;
    }

    public Long getId() {
        return id;
    }

    public void setBody(String body) {
        this.body = body;
    }
}
