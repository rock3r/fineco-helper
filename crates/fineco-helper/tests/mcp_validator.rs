//! Guards the committed remote-MCP regression harness
//! (`e2e/spike/validate-mcp.sh`): its `EXPECTED` tool list must stay in sync with
//! the gateway's registered MCP tools (so the check can't silently drift past an
//! added/removed tool), and it must carry no host-specific values.

use std::collections::BTreeSet;
use std::path::PathBuf;

fn repo_file(rel: &str) -> String {
    // CARGO_MANIFEST_DIR = crates/fineco-helper; the repo root is two up.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../..");
    p.push(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn mcp_validator_expected_tools_match_the_gateway() {
    // The gateway's registered MCP tools: `name = "snake_case"` (the #[tool(name=…)]
    // attribute). Filter to tool-name shape so any unrelated `name = "…"` is ignored.
    let gw = repo_file("crates/fineco-gateway/src/lib.rs");
    let registered: BTreeSet<&str> = gw
        .match_indices("name = \"")
        .filter_map(|(i, m)| {
            let rest = &gw[i + m.len()..];
            let end = rest.find('"')?;
            let name = &rest[..end];
            (name.contains('_') && name.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
                .then_some(name)
        })
        .collect();

    // The validator's EXPECTED="a b c …" list.
    let script = repo_file("e2e/spike/validate-mcp.sh");
    let expected: BTreeSet<&str> = script
        .lines()
        .find(|l| l.trim_start().starts_with("EXPECTED="))
        .expect("validate-mcp.sh must declare EXPECTED=")
        .split('"')
        .nth(1)
        .expect("EXPECTED must be a quoted list")
        .split_whitespace()
        .collect();

    assert_eq!(
        registered,
        expected,
        "e2e/spike/validate-mcp.sh EXPECTED must match the gateway's registered tools.\n  \
         in gateway but not validator: {:?}\n  in validator but not gateway: {:?}",
        registered.difference(&expected).collect::<Vec<_>>(),
        expected.difference(&registered).collect::<Vec<_>>(),
    );
    assert_eq!(registered.len(), 19, "expected 19 registered tools");
}

#[test]
fn mcp_validator_has_no_host_specific_values() {
    // The URL + service token come from the env file (cf-spike.env), never baked in.
    let script = repo_file("e2e/spike/validate-mcp.sh");
    assert!(
        script.contains("${SPIKE_PUBLIC_URL") && script.contains("source \"$ENVFILE\""),
        "the validator must read the URL + creds from the env file"
    );
    // The host comes from $SPIKE_PUBLIC_URL (asserted above), so no real hostname is
    // baked in; here we additionally guard that no credential literal is committed.
    // (Deliberately no real host substrings in this assertion — this is a public repo.)
    for forbidden in ["CF_ACCESS_CLIENT_SECRET=", "CF_ACCESS_CLIENT_ID="] {
        assert!(
            !script.contains(forbidden),
            "the committed validator must carry no baked-in credential ({forbidden:?})"
        );
    }
    // The service token must NOT be exported into curl's environment (readable via
    // /proc/<pid>/environ): the env file is sourced WITHOUT `set -a`, and curl gets the
    // credentials only via `--config -` on stdin.
    assert!(
        !script.lines().any(|l| l.trim_start().starts_with("set -a")),
        "validate-mcp.sh must not `set -a` (it would export the CF token into curl's env)"
    );
    // Strip any inherited export attribute too: if the caller already exported the CF
    // vars, plain sourcing keeps them exported, so curl would still inherit the token.
    assert!(
        script.contains("export -n CF_ACCESS_CLIENT_ID CF_ACCESS_CLIENT_SECRET"),
        "validate-mcp.sh must `export -n` the CF vars to clear any inherited export"
    );
    assert!(
        script.contains("--config -"),
        "the CF service token must reach curl via `--config -` (stdin), never argv/env"
    );
}

#[test]
fn the_spike_verifier_does_not_export_the_cf_token() {
    // verify-spike.sh feeds the CF token to curl via `--config -` (stdin) too, so it must
    // NOT `set -a` (export it into curl/docker child env, readable via /proc/<pid>/environ)
    // and must `export -n` to clear any inherited attribute — same rule as validate-mcp.sh.
    let script = repo_file("e2e/spike/verify-spike.sh");
    assert!(
        !script.lines().any(|l| l.trim_start().starts_with("set -a")),
        "verify-spike.sh must not `set -a` (it would export the CF token into child env)"
    );
    assert!(
        script.contains("export -n CF_ACCESS_CLIENT_ID CF_ACCESS_CLIENT_SECRET"),
        "verify-spike.sh must `export -n` the CF vars to clear any inherited export"
    );
}
