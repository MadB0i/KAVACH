# Contributing to KAVACH

## Getting Started

1. Ensure you have Rust 1.85+ installed.
2. Clone the repository.
3. Run `cargo build --workspace --all-features` to verify the build.
4. Run `cargo test --workspace --all-features` to verify tests pass.

## Development Workflow

1. Create a feature branch from `main`.
2. Make your changes.
3. Run the full verification suite before opening a PR:
   ```bash
   cargo fmt --all -- --check
   cargo check --workspace --all-targets --all-features
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace --all-features
   cargo test --release --workspace --all-features
   cargo doc --workspace --no-deps
   cargo bench --workspace --no-run
   npm --prefix dashboard run lint
   npm --prefix dashboard run test
   npm --prefix dashboard run build
   ```
4. Open a pull request against `main` using the PR template.

## Code Style

- Follow existing patterns in the codebase.
- All public items must have doc comments (enforced by `missing_docs = "warn"`).
- Never use `unsafe` code (forbidden workspace-wide).
- Avoid `unwrap()` and `expect()` in production code; use proper error handling.
- Tests may use `unwrap()` with explicit `#[allow(clippy::unwrap_used)]`.

## Testing

- Unit tests go in a `#[cfg(test)] mod tests { ... }` block at the bottom of
  the source file containing the code being tested.
- Integration tests go in `tests/` at the crate root.
- Property-based tests go in `proptests.rs` inside `src/`.
- Benchmarks go in `benches/`.
- Dashboard tests go in `dashboard/src/__tests__/`.

## Pull Request Checklist

- [ ] All verification commands pass
- [ ] New code has tests
- [ ] No secrets or credentials committed
- [ ] Documentation updated if applicable
- [ ] Changelog entry added if user-facing change
