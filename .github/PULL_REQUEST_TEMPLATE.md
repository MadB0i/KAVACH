## Description

<!-- Briefly describe the change and why it's needed. -->

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behavior)
- [ ] Documentation update
- [ ] CI / build system change
- [ ] Other (please describe):

## Checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo check --workspace --all-targets --all-features` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --workspace --all-features` passes
- [ ] `cargo doc --workspace --no-deps` passes
- [ ] `npm --prefix dashboard run lint` passes
- [ ] `npm --prefix dashboard run test` passes
- [ ] `npm --prefix dashboard run build` passes
- [ ] New code has tests
- [ ] No secrets or credentials committed
- [ ] Documentation updated if applicable

## Related Issue

<!-- Link to the related issue, e.g. "Closes #123" -->
