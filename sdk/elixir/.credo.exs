# Credo, --strict, as the conformance suite runs it (integrations/phoenix/test.sh). The exceptions keep the names
# the other SDKs give them (Refused, NotFound, CallError, NotSignedIn, ConnectionProblem), whatever Credo would
# make them share.
%{
  configs: [
    %{
      name: "default",
      files: %{included: ["lib/", "mix.exs"]},
      strict: true,
      checks: %{disabled: [{Credo.Check.Consistency.ExceptionNames, []}]}
    }
  ]
}
