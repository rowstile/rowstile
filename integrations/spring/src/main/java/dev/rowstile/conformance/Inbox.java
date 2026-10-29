package dev.rowstile.conformance;

import org.springframework.data.jpa.repository.JpaRepository;

/** The messages, as Spring Data reads and writes them: the database filters them. */
public interface Inbox extends JpaRepository<Message, Long> {}
