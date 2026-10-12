# Oracle Zero Trust AI Lab

A gated, documentation-first laboratory that studies how Oracle APEX and
Oracle Deep Data Security (end-user security contexts, data roles and data
grants) can enforce least-privilege data access for AI-assisted database
applications. Identity federation with an external identity provider is
planned for later phases.

## Status

- Early stage. Lab sources are proposed on feature branches and reviewed
  through pull requests before they reach `main`.
- No laboratory step has been executed against a database as part of this
  repository. No test results, measurements or security guarantees are
  claimed.
- Each phase advances only after explicit human approval.

## Principles

- Synthetic data only. The repository never contains production data,
  credentials, generated secrets, wallets, logs, execution state or details
  of a specific environment (hostnames, ports, local paths, database
  identifiers). Local settings are supplied through templates.
- Official Oracle documentation is the primary reference.
- Verified facts, assumptions, hypotheses and open questions are tracked
  separately and labeled as such.
- Database-enforced security is the subject under study; application-level
  authorization is documented as a separate layer, not as a substitute.

## License

No license has been selected for this repository yet.

## Trademarks

Oracle, Java, MySQL and NetSuite are registered trademarks of Oracle and/or
its affiliates. This project is independent and is not affiliated with or
endorsed by Oracle.
