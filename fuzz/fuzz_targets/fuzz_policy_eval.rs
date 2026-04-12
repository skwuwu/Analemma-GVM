#![no_main]
//! Structure-aware ABAC policy evaluation fuzzer.
//!
//! Generates arbitrary operation metadata (agent_id, operation name,
//! resource attributes) and evaluates against the policy engine.
//! Inputs are always structurally valid so the engine exercises
//! condition matching (Eq, NotEq, Regex, Contains, In) and
//! max_strict() composition.

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

struct PolicyFixture {
    policy: gvm_proxy::policy::PolicyEngine,
    _tempdir: tempfile::TempDir,
}

static POLICY: OnceLock<PolicyFixture> = OnceLock::new();

fn get_policy() -> &'static gvm_proxy::policy::PolicyEngine {
    &POLICY
        .get_or_init(|| {
            let dir = tempfile::tempdir().expect("temp dir");
            let policy_dir = dir.path().join("policies");
            std::fs::create_dir_all(&policy_dir).expect("create dir");
            // Copy the production policy file — guaranteed to parse.
            // Try both CWD=repo-root and CWD=fuzz/ (CI runs `cd fuzz` before cargo fuzz run).
            let candidates = [
                "config/policies/global.toml",
                "../config/policies/global.toml",
            ];
            let mut copied = false;
            for src in &candidates {
                let p = std::path::Path::new(src);
                if p.exists() {
                    std::fs::copy(p, policy_dir.join("global.toml")).expect("copy policy");
                    copied = true;
                    break;
                }
            }
            if !copied {
                // Minimal valid policy — no conditions, just a default delay
                std::fs::write(
                    policy_dir.join("global.toml"),
                    "[[rules]]\nid = \"fuzz-default\"\npriority = 50\nlayer = \"Global\"\n\n\
                     [rules.decision]\ntype = \"Delay\"\nmilliseconds = 300\n",
                )
                .expect("write fallback policy");
            }
            let policy =
                gvm_proxy::policy::PolicyEngine::load(&policy_dir).expect("load policy");
            PolicyFixture {
                policy,
                _tempdir: dir,
            }
        })
        .policy
}

/// Structured policy evaluation input.
#[derive(Debug)]
struct PolicyInput {
    operation: String,
    agent_id: String,
    resource_tier: String,
    resource_sensitivity: String,
}

impl<'a> Arbitrary<'a> for PolicyInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let ops = [
            "gvm.payment.charge",
            "gvm.data.read",
            "gvm.data.delete",
            "gvm.admin.deploy",
            "test.operation",
            "custom.workflow.step",
        ];
        let tiers = ["Internal", "External", "CustomerFacing"];
        let sens = ["Low", "Medium", "High", "Critical"];
        let agents = ["agent-001", "finance-bot", "admin", "untrusted"];

        let op_idx: usize = u.int_in_range(0..=ops.len() - 1)?;
        let agent_idx: usize = u.int_in_range(0..=agents.len() - 1)?;
        let tier_idx: usize = u.int_in_range(0..=tiers.len() - 1)?;
        let sens_idx: usize = u.int_in_range(0..=sens.len() - 1)?;

        // Sometimes use a completely random operation name
        let use_random: bool = u.arbitrary()?;
        let operation = if use_random {
            let len: usize = u.int_in_range(1..=50)?;
            (0..len)
                .map(|_| Ok(u.int_in_range(b'a'..=b'z')? as char))
                .collect::<arbitrary::Result<String>>()?
        } else {
            ops[op_idx].to_string()
        };

        Ok(Self {
            operation,
            agent_id: agents[agent_idx].to_string(),
            resource_tier: tiers[tier_idx].to_string(),
            resource_sensitivity: sens[sens_idx].to_string(),
        })
    }
}

fuzz_target!(|input: PolicyInput| {
    use gvm_types::{OperationMetadata, ResourceDescriptor, SubjectDescriptor};

    let tier = match input.resource_tier.as_str() {
        "Internal" => gvm_types::ResourceTier::Internal,
        "CustomerFacing" => gvm_types::ResourceTier::CustomerFacing,
        _ => gvm_types::ResourceTier::External,
    };
    let sensitivity = match input.resource_sensitivity.as_str() {
        "Low" => gvm_types::Sensitivity::Low,
        "High" => gvm_types::Sensitivity::High,
        "Critical" => gvm_types::Sensitivity::Critical,
        _ => gvm_types::Sensitivity::Medium,
    };

    let op = OperationMetadata {
        operation: input.operation,
        resource: ResourceDescriptor {
            service: "fuzz-service".to_string(),
            identifier: None,
            tier,
            sensitivity,
        },
        subject: SubjectDescriptor {
            agent_id: input.agent_id,
            tenant_id: None,
            session_id: "fuzz-session".to_string(),
        },
        context: gvm_types::OperationContext {
            attributes: std::collections::HashMap::new(),
        },
        payload: gvm_types::PayloadDescriptor::default(),
    };

    let _ = get_policy().evaluate(&op);
});
