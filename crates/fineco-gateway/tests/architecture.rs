//! Structural security invariant: the internet-facing gateway must never carry
//! `fineco-store`, `fineco-worker`, or `fineco-live` in its **runtime** dependency
//! closure. It reaches stored data only over the snapshot-query socket and holds
//! no credentials — so a direct (normal) dependency on the store or the credential
//! worker would breach the process boundary (plan "Process Boundaries"). And
//! `fineco-live` is the client+protocol for `fineco-live.sock`: depending on it
//! would give the gateway a live-socket client, which the plan forbids ("Must
//! not: Talk to the live-refresh socket"). This compile-time barrier backs the
//! runtime `fineco-ipc-live` socket-group isolation.
//!
//! Dev-dependencies legitimately use `fineco-store`/`fineco-query` to stand up a
//! worker in tests, so this check follows only normal (and build) edges, never
//! `dev` edges. It shells out to `cargo metadata` (available locally and in CI).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::process::Command;

use serde_json::Value;

/// Crates the gateway's runtime closure must never reach.
const FORBIDDEN: [&str; 3] = ["fineco-store", "fineco-worker", "fineco-live"];

#[test]
fn gateway_runtime_closure_excludes_store_and_worker() {
    let metadata = cargo_metadata();
    let resolve = &metadata["resolve"];
    let nodes = resolve["nodes"]
        .as_array()
        .expect("resolve.nodes is an array");

    // Map every package id to its name, and to its normal/build dependency ids.
    let mut name_of: BTreeMap<&str, &str> = BTreeMap::new();
    let mut runtime_deps: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in nodes {
        let id = node["id"].as_str().expect("node id");
        let mut deps = Vec::new();
        for dep in node["deps"].as_array().expect("node.deps is an array") {
            // dep_kinds entries have `kind`: null (normal), "dev", or "build".
            let is_runtime = dep["dep_kinds"]
                .as_array()
                .expect("dep_kinds is an array")
                .iter()
                .any(|k| {
                    let kind = &k["kind"];
                    kind.is_null() || kind == "build"
                });
            if is_runtime {
                deps.push(dep["pkg"].as_str().expect("dep.pkg"));
            }
        }
        runtime_deps.insert(id, deps);
    }
    for package in metadata["packages"]
        .as_array()
        .expect("packages is an array")
    {
        let id = package["id"].as_str().expect("package id");
        let name = package["name"].as_str().expect("package name");
        name_of.insert(id, name);
    }

    let gateway_id = name_of
        .iter()
        .find_map(|(&id, &name)| (name == "fineco-gateway").then_some(id))
        .expect("fineco-gateway is a workspace package");

    // BFS the runtime closure from the gateway.
    let mut reachable: BTreeSet<&str> = BTreeSet::new();
    let mut queue: VecDeque<&str> = VecDeque::from([gateway_id]);
    while let Some(id) = queue.pop_front() {
        for &dep in runtime_deps.get(id).into_iter().flatten() {
            if reachable.insert(dep) {
                queue.push_back(dep);
            }
        }
    }

    let reachable_names: BTreeSet<&str> = reachable
        .iter()
        .filter_map(|id| name_of.get(id).copied())
        .collect();
    for forbidden in FORBIDDEN {
        assert!(
            !reachable_names.contains(forbidden),
            "fineco-gateway runtime closure must not include {forbidden}; reachable: {reachable_names:?}"
        );
    }
}

/// Run `cargo metadata` for the current workspace and parse it.
fn cargo_metadata() -> Value {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(cargo)
        .args(["metadata", "--format-version", "1"])
        .output()
        .expect("run cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse cargo metadata JSON")
}
