package dev.rowstile.conformance;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * The conformance app: no permission checks anywhere. rowstile signs each transaction in as the request's user, the
 * database filters reads and refuses writes, and the SDK turns refusals into 403 and hidden rows into 404.
 */
@SpringBootApplication
public class ConformanceApp {
    public static void main(String[] args) {
        SpringApplication.run(ConformanceApp.class, args);
    }
}
