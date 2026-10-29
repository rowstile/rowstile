package dev.rowstile.conformance;

import org.springframework.data.jpa.repository.JpaRepository;

/** The projects, as Spring Data reads and writes them: the database filters them. */
public interface Projects extends JpaRepository<Project, Long> {}
