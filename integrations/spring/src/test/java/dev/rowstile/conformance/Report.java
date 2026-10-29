package dev.rowstile.conformance;

import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;

/** Each check's line, as the other suites print theirs: {@code ok    7: ...}, or {@code FAIL  7: ...} and why. */
public class Report implements TestExecutionListener {
    @Override
    public void executionFinished(TestIdentifier test, TestExecutionResult result) {
        if (!test.isTest()) {
            return;
        }
        if (result.getStatus() == TestExecutionResult.Status.SUCCESSFUL) {
            System.out.println("ok    " + test.getDisplayName());
        } else {
            System.out.println("FAIL  " + test.getDisplayName() + ": "
                    + result.getThrowable().map(Throwable::toString).orElse(result.getStatus().toString()));
        }
    }
}
