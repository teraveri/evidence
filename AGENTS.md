# Agent guidance

This workspace defines the shared `evidence-protocol` wire contract and
`evidence-core` bounded parsing/snapshot checks. Keep collector I/O, policy,
reference appraisal, network transport, and application admission in their
owning repositories. A wire or binding change needs an explicit version and
matching compatibility tests for both consumers.

Read `README.md` before editing. Run `cargo test --locked --workspace` and
`cargo fmt --all -- --check` for changes here. Inspect `git diff --check` before
handoff.

Exclude `target/`, caches, generated binaries, and logs from broad searches.
Never print or attach private keys, credentials, or raw live evidence to model
context, issues, or PRs. Synthetic test fixtures and redacted metadata are
sufficient for code review.
