#![allow(clippy::unwrap_used, clippy::print_stdout, missing_docs)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use kavach_redaction::{CompositeRedactor, Redactor};

fn bench_redaction(c: &mut Criterion) {
    let redactor = CompositeRedactor::builder()
        .with_bearer(true)
        .with_jwt(true)
        .with_pem(true)
        .with_assignments(true)
        .with_github(true)
        .with_aws(true)
        .build();
    let mut group = c.benchmark_group("redaction");
    group.bench_function("plain_text", |b| {
        b.iter(|| redactor.redact_text(black_box("The quick brown fox jumps over the lazy dog.")));
    });
    group.bench_function("with_bearer_token", |b| {
        b.iter(|| {
            redactor.redact_text(black_box(
                "Authorization: Bearer sk-bench-secret-token-for-testing",
            ))
        });
    });
    group.bench_function("with_api_key", |b| {
        b.iter(|| {
            redactor.redact_text(black_box(
                "export API_KEY = a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
            ))
        });
    });
    group.bench_function("with_github_token", |b| {
        b.iter(|| redactor.redact_text(black_box("ghp_abcdefghijklmnopqrstuvwxyz0123456789ab")));
    });
    group.finish();
}

criterion_group!(benches, bench_redaction);
criterion_main!(benches);
