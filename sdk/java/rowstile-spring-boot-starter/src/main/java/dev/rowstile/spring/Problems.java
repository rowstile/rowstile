package dev.rowstile.spring;

import dev.rowstile.DatabaseError;
import dev.rowstile.Errors;
import dev.rowstile.NotFound;
import dev.rowstile.Problem;
import dev.rowstile.Refused;
import java.net.URI;
import java.sql.SQLException;
import java.util.Optional;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.dao.DataAccessException;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.TransactionException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * rowstile's answers as problem details (RFC 9457, {@code application/problem+json}): a refusal 403 with the rule and
 * the reason, a row the user can't see 404, an entity changed meanwhile 409; a call the database turns down that is
 * no refusal, as its code's page says, with the database's words (401, 404, 400, 409). Any other error is left as it
 * is: the app's mistakes stay errors, a 500. Last among the app's advice: a handler of the app's own comes first.
 */
@RestControllerAdvice
@Order(Ordered.LOWEST_PRECEDENCE)
public class Problems {
    /**
     * rowstile's own answers, and the database's errors, however they come: JDBC's, Spring's translation of them, a
     * transaction's, JPA's own (Spring tries an exception's causes too, and Postgres's error is an SQLException):
     * answered if they are rowstile's.
     */
    @ExceptionHandler({
        Refused.class,
        NotFound.class,
        Conflict.class,
        DataAccessException.class,
        TransactionException.class,
        SQLException.class,
        DatabaseError.class
    })
    public ResponseEntity<ProblemDetail> answer(Exception e) throws Exception {
        return answered(e);
    }

    /** {@code e}'s answer, or {@code e} itself, thrown again, when it is none of rowstile's. */
    static ResponseEntity<ProblemDetail> answered(Exception e) throws Exception {
        Optional<Problem> problem = e instanceof Conflict c ? Optional.of(c.problem()) : Errors.problem(e);
        if (problem.isEmpty()) {
            throw e; // (the same exception: Spring goes on with it, as if this handler weren't there)
        }
        return response(problem.get());
    }

    /** A problem as Spring's {@link ProblemDetail}, its own members beside the standard ones. */
    static ResponseEntity<ProblemDetail> response(Problem problem) {
        ProblemDetail body = ProblemDetail.forStatus(problem.status());
        body.setType(URI.create(problem.type()));
        body.setTitle(problem.title());
        body.setDetail(problem.detail());
        problem.members().forEach(body::setProperty);
        return ResponseEntity.status(problem.status()).contentType(MediaType.APPLICATION_PROBLEM_JSON).body(body);
    }
}
