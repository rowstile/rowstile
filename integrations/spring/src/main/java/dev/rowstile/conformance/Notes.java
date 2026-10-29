package dev.rowstile.conformance;

import org.springframework.data.jpa.repository.JpaRepository;

/** The notes, as Spring Data reads and writes them: the database filters them. */
public interface Notes extends JpaRepository<Note, Long> {}
