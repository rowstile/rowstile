package dev.rowstile.conformance

import org.junit.platform.engine.TestExecutionResult
import org.junit.platform.launcher.TestExecutionListener
import org.junit.platform.launcher.TestIdentifier

/** Each check's line, as the other suites print theirs: `ok    7: ...`, or `FAIL  7: ...` and why. */
class Report : TestExecutionListener {
    override fun executionFinished(test: TestIdentifier, result: TestExecutionResult) {
        if (!test.isTest) return
        if (result.status == TestExecutionResult.Status.SUCCESSFUL) {
            println("ok    ${test.displayName}")
        } else {
            println("FAIL  ${test.displayName}: ${result.throwable.map(Throwable::toString).orElse(result.status.toString())}")
        }
    }
}
