package dev.rowstile.conformance;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** A project: its owner and members edit it, anyone may read a public one. */
@Entity
@Table(schema = "app", name = "projects")
public class Project {
    @Id
    private Long id;

    @Column(name = "owner_id")
    private long ownerId;

    private String name;

    @Column(name = "public")
    private boolean open;

    protected Project() {}

    public Long getId() {
        return id;
    }
}
