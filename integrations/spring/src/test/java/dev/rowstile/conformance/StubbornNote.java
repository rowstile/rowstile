package dev.rowstile.conformance;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.SQLUpdate;
import org.hibernate.jdbc.Expectation;

/** A note whose update never matches its row, though the rules allow it: as if it changed since it was read. */
@Entity
@Table(schema = "app", name = "notes")
@SQLUpdate(sql = "UPDATE app.notes SET body = ? WHERE id = ? AND false", verify = Expectation.RowCount.class)
public class StubbornNote {
    @Id
    private Long id;

    private String body;

    @Column(name = "project_id", updatable = false)
    private long projectId;

    @Column(name = "author_id", updatable = false)
    private long authorId;

    protected StubbornNote() {}

    void setBody(String body) {
        this.body = body;
    }
}
