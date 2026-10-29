package dev.rowstile.conformance;

import org.springframework.data.jpa.repository.JpaRepository;

/** The folders, as Spring Data reads and writes them: the database filters them. */
public interface Folders extends JpaRepository<Folder, Long> {}
