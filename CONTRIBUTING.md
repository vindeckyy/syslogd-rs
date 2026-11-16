# Contributing to syslogd-rs

Thanks for stopping by. The project handles configuration that
protects system logs, so changes that silently narrow the supported
subset are rejected unless they come with an explicit test showing
the tradeoff in `README.md`'s support matrix.

## Development setup

- Rust 1.99+ (`rust-toolchain.toml` pins `stable`)
- `cargo test --offline` for unit and integration behavior
- Linux is the runtime target; macOS builds run for tests and
  cross-checks. Docker is welcome for container verification
  where a daemon is available.

## Pull requests

- Keep the change contained; if you touch wire formats, templates,
  or the configuration grammar, add a test that fails without the
  change and passes with it.
- Run `cargo fmt --all` and `cargo clippy -- -D warnings` before
  pushing; CI enforces both.
- Describe user-visible behavior (what config now validates,
  what a client sees) rather than only what moved internally.

## Commit style

Small, descriptive commits, e.g. `config: reject unknown template
in strict mode`. A PR description should state what the change
does, why, and what you ran to verify it.
