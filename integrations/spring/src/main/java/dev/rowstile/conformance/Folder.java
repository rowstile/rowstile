package dev.rowstile.conformance;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** A folder, inside another or at the top: its owner and the owners of the folders above edit it. */
@Entity
@Table(schema = "app", name = "folders")
public class Folder {
    @Id
    private Long id;

    @Column(name = "parent_id")
    private Long parentId;

    @Column(name = "owner_id")
    private long ownerId;

    private String name;

    protected Folder() {}

    public void setParentId(Long parentId) {
        this.parentId = parentId;
    }
}
