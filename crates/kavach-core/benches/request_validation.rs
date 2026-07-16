#![allow(clippy::unwrap_used, clippy::print_stdout, missing_docs)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use kavach_core::ids::{AgentId, RequestId, SessionId};
use kavach_core::request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
use kavach_core::resource::{CommandResource, NormalizedPath, Resource};

fn bench_request_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("request_validation");
    group.bench_function("valid_file_read", |b| {
        let req = ToolRequest::new(
            RequestId::new("bench-req").unwrap(),
            AgentSubjectBuilder::new(
                AgentId::new("bench-agent").unwrap(),
                SessionId::new("bench-sess").unwrap(),
            )
            .build(),
            Operation::FileRead {
                max_bytes: Some(4096),
            },
            Resource::file("/workspace/src/main.rs").unwrap(),
            RequestContext::new(None, None, None, None, false).unwrap(),
        );
        b.iter(|| req.validate());
    });
    group.bench_function("valid_command_execute", |b| {
        let cmd = CommandResource::new("echo", vec!["hello".into()]).unwrap();
        let req = ToolRequest::new(
            RequestId::new("bench-req").unwrap(),
            AgentSubjectBuilder::new(
                AgentId::new("bench-agent").unwrap(),
                SessionId::new("bench-sess").unwrap(),
            )
            .build(),
            Operation::CommandExecute,
            Resource::Command(cmd),
            RequestContext::new(None, None, None, None, false).unwrap(),
        );
        b.iter(|| req.validate());
    });
    group.finish();
}

fn bench_path_normalization(c: &mut Criterion) {
    c.bench_function("path_normalize_short", |b| {
        b.iter(|| NormalizedPath::new(black_box("/workspace/src/main.rs")));
    });
    c.bench_function("path_normalize_with_dotdot", |b| {
        b.iter(|| NormalizedPath::new(black_box("/workspace/../src/./main.rs")));
    });
}

fn bench_request_digest(c: &mut Criterion) {
    use kavach_core::digest::compute_request_digest;
    let req = ToolRequest::new(
        RequestId::new("digest-bench").unwrap(),
        AgentSubjectBuilder::new(
            AgentId::new("bench-agent").unwrap(),
            SessionId::new("bench-sess").unwrap(),
        )
        .build(),
        Operation::FileRead { max_bytes: None },
        Resource::file("/workspace/data/large-file.bin").unwrap(),
        RequestContext::new(None, None, None, None, false).unwrap(),
    );
    c.bench_function("request_digest", |b| {
        b.iter(|| compute_request_digest(black_box(&req)));
    });
}

criterion_group!(
    benches,
    bench_request_validation,
    bench_path_normalization,
    bench_request_digest
);
criterion_main!(benches);
