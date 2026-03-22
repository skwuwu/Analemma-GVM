use crate::types::*;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

// ─── ABAC Policy Model (PART 3) ───

/// Policy rule as defined in TOML config files
#[derive(Deserialize, Clone, Debug)]
struct PolicyRuleConfig {
    id: String,
    priority: u32,
    layer: String,
    description: String,
    #[serde(default)]
    conditions: Vec<ConditionConfig>,
    decision: DecisionConfig,
}

#[derive(Deserialize, Clone, Debug)]
struct ConditionConfig {
    field: String,
    operator: String,
    value: serde_json::Value,
}

#[derive(Deserialize, Clone, Debug)]
struct DecisionConfig {
    #[serde(rename = "type")]
    decision_type: String,
    milliseconds: Option<u64>,
    reason: Option<String>,
    urgency: Option<String>,
    max_per_minute: Option<u64>,
    alert_level: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
struct PolicyFile {
    rules: Vec<PolicyRuleConfig>,
}

/// Compiled policy rule ready for evaluation
#[derive(Clone, Debug)]
pub struct PolicyRule {
    pub id: String,
    pub priority: u32,
    pub layer: PolicyLayer,
    pub description: String,
    pub conditions: Vec<Condition>,
    pub decision: EnforcementDecision,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyLayer {
    /// Cannot be overridden
    Global,
    /// Can only be stricter than Global
    Tenant,
    /// Can only be stricter than Tenant
    Agent,
}

#[derive(Clone, Debug)]
pub struct Condition {
    /// Field path to evaluate, e.g. "operation", "resource.tier", "context.amount"
    pub field: String,
    /// Comparison operator
    pub operator: Operator,
    /// Comparison value
    pub value: serde_json::Value,
    /// Pre-compiled regex (only populated when operator is Regex)
    pub compiled_regex: Option<regex::Regex>,
}

#[derive(Clone, Debug)]
pub enum Operator {
    Eq,
    NotEq,
    Gt,
    Lt,
    Gte,
    Lte,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
    In,
    NotIn,
}

// ─── Policy Conflict Detection ───

/// Warning about a potential policy conflict or ineffective rule.
/// Emitted at startup to alert operators without blocking proxy start.
#[derive(Clone, Debug)]
pub struct PolicyWarning {
    pub severity: WarningSeverity,
    pub kind: WarningKind,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WarningSeverity {
    /// Ambiguous but not necessarily wrong (e.g. duplicate priority)
    Warning,
    /// Likely a mistake (e.g. contradictory decisions on same conditions)
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WarningKind {
    /// Two rules in the same layer share the same priority
    DuplicatePriority,
    /// Two rules have overlapping conditions but opposite decisions
    ContradictoryDecision,
    /// A lower-layer rule is overridden by a stricter upper-layer rule
    IneffectiveRule,
}

impl std::fmt::Display for PolicyWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let severity_tag = match self.severity {
            WarningSeverity::Warning => "WARNING",
            WarningSeverity::Error => "ERROR",
        };
        write!(f, "[{}] {}", severity_tag, self.message)
    }
}

/// ABAC Policy Engine — evaluates operation metadata against hierarchical rules.
/// Hierarchy: Global > Tenant > Agent (lower layers can only be stricter).
pub struct PolicyEngine {
    global_rules: Vec<PolicyRule>,
    tenant_rules: HashMap<String, Vec<PolicyRule>>,
    agent_rules: HashMap<String, Vec<PolicyRule>>,
}

impl PolicyEngine {
    /// Load all policy files from a directory.
    /// - global.toml → Global layer
    /// - tenant-{name}.toml → Tenant layer
    /// - agent-{name}.toml → Agent layer
    pub fn load(dir: &Path) -> Result<Self> {
        let mut global_rules = Vec::new();
        let mut tenant_rules: HashMap<String, Vec<PolicyRule>> = HashMap::new();
        let mut agent_rules: HashMap<String, Vec<PolicyRule>> = HashMap::new();

        if !dir.exists() {
            tracing::warn!(
                "Policy directory not found: {}. Starting with empty policy set.",
                dir.display()
            );
            return Ok(Self {
                global_rules,
                tenant_rules,
                agent_rules,
            });
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }

            let filename = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();

            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read policy file: {}", path.display()))?;
            let file: PolicyFile = toml::from_str(&content)
                .with_context(|| format!("Failed to parse policy file: {}", path.display()))?;

            for rule_cfg in file.rules {
                let rule = compile_rule(&rule_cfg)?;

                if filename == "global" {
                    global_rules.push(rule);
                } else if let Some(tenant_name) = filename.strip_prefix("tenant-") {
                    tenant_rules
                        .entry(tenant_name.to_string())
                        .or_default()
                        .push(rule);
                } else if let Some(agent_name) = filename.strip_prefix("agent-") {
                    agent_rules
                        .entry(agent_name.to_string())
                        .or_default()
                        .push(rule);
                } else {
                    tracing::warn!(
                        "Unknown policy file naming: {}. Expected global.toml, tenant-*.toml, or agent-*.toml",
                        path.display()
                    );
                }
            }
        }

        // Sort each rule set by priority (ascending = higher priority first)
        global_rules.sort_by_key(|r| r.priority);
        for rules in tenant_rules.values_mut() {
            rules.sort_by_key(|r| r.priority);
        }
        for rules in agent_rules.values_mut() {
            rules.sort_by_key(|r| r.priority);
        }

        // Validate policy conflicts at startup
        let warnings = validate_conflicts(&global_rules, &tenant_rules, &agent_rules);
        for w in &warnings {
            match w.severity {
                WarningSeverity::Warning => tracing::warn!("{}", w),
                WarningSeverity::Error => tracing::error!("{}", w),
            }
        }
        if !warnings.is_empty() {
            tracing::warn!(
                count = warnings.len(),
                "Policy conflict check complete — review warnings above"
            );
        }

        tracing::info!(
            global = global_rules.len(),
            tenants = tenant_rules.len(),
            agents = agent_rules.len(),
            "Policy engine loaded"
        );

        Ok(Self {
            global_rules,
            tenant_rules,
            agent_rules,
        })
    }

    /// Evaluate an operation against all policy layers.
    /// Returns the strictest applicable enforcement decision.
    ///
    /// Summary counts for the startup banner.
    pub fn summary(&self) -> (usize, usize, usize) {
        let global = self.global_rules.len();
        let tenants = self.tenant_rules.len();
        let agents = self.agent_rules.len();
        (global, tenants, agents)
    }

    /// Algorithm (PART 3.4):
    /// 1. Evaluate Global rules (Deny → immediate return)
    /// 2. Evaluate Tenant rules (can only be stricter than Global)
    /// 3. Evaluate Agent rules (can only be stricter than Tenant)
    /// 4. Final decision = strictest match across all layers
    pub fn evaluate(&self, operation: &OperationMetadata) -> (EnforcementDecision, Option<String>) {
        let mut final_decision = EnforcementDecision::Allow;
        let mut matched_rule_id: Option<String> = None;

        // Layer 1: Global rules
        // Uses >= so that any Global match replaces the initial Allow default
        // (same strictness still adopts the Global rule's decision and rule_id)
        if let Some((decision, rule_id)) = self.evaluate_layer(&self.global_rules, operation) {
            if matches!(decision, EnforcementDecision::Deny { .. }) {
                return (decision, Some(rule_id));
            }
            if decision.strictness() >= final_decision.strictness() {
                final_decision = decision;
                matched_rule_id = Some(rule_id);
            }
        }

        // Layer 2: Tenant rules
        // Uses > (strictly greater) so lower layers only override when actually stricter
        if let Some(tenant_id) = &operation.subject.tenant_id {
            if let Some(rules) = self.tenant_rules.get(tenant_id) {
                if let Some((decision, rule_id)) = self.evaluate_layer(rules, operation) {
                    if matches!(decision, EnforcementDecision::Deny { .. }) {
                        return (decision, Some(rule_id));
                    }
                    if decision.strictness() > final_decision.strictness() {
                        final_decision = decision;
                        matched_rule_id = Some(rule_id);
                    }
                }
            }
        }

        // Layer 3: Agent rules
        if let Some(rules) = self.agent_rules.get(&operation.subject.agent_id) {
            if let Some((decision, rule_id)) = self.evaluate_layer(rules, operation) {
                if matches!(decision, EnforcementDecision::Deny { .. }) {
                    return (decision, Some(rule_id));
                }
                if decision.strictness() > final_decision.strictness() {
                    final_decision = decision;
                    matched_rule_id = Some(rule_id);
                }
            }
        }

        (final_decision, matched_rule_id)
    }

    /// Evaluate a single layer's rules. Returns the first matching rule's decision.
    /// Rules are pre-sorted by priority (ascending), so the first match wins for that layer.
    fn evaluate_layer(
        &self,
        rules: &[PolicyRule],
        operation: &OperationMetadata,
    ) -> Option<(EnforcementDecision, String)> {
        for rule in rules {
            if rule_matches(rule, operation) {
                return Some((rule.decision.clone(), rule.id.clone()));
            }
        }
        None
    }
}

/// Check if all conditions of a rule match against the operation metadata.
/// Conditions are AND-combined: all must match for the rule to apply.
fn rule_matches(rule: &PolicyRule, operation: &OperationMetadata) -> bool {
    // No conditions = unconditional match (e.g. fallback rules)
    if rule.conditions.is_empty() {
        return true;
    }

    rule.conditions.iter().all(|cond| {
        let field_value = resolve_field(&cond.field, operation);
        evaluate_condition(
            &cond.operator,
            &field_value,
            &cond.value,
            &cond.compiled_regex,
        )
    })
}

/// Resolve a dotted field path to its JSON value from the operation metadata.
fn resolve_field(field: &str, operation: &OperationMetadata) -> serde_json::Value {
    match field {
        "operation" => serde_json::Value::String(operation.operation.clone()),

        "resource.service" => serde_json::Value::String(operation.resource.service.clone()),
        "resource.identifier" => match &operation.resource.identifier {
            Some(id) => serde_json::Value::String(id.clone()),
            None => serde_json::Value::Null,
        },
        "resource.tier" => {
            serde_json::Value::String(tier_as_policy_str(&operation.resource.tier).to_string())
        }
        "resource.sensitivity" => serde_json::Value::String(
            sensitivity_as_policy_str(&operation.resource.sensitivity).to_string(),
        ),

        "subject.agent_id" => serde_json::Value::String(operation.subject.agent_id.clone()),
        "subject.tenant_id" => match &operation.subject.tenant_id {
            Some(id) => serde_json::Value::String(id.clone()),
            None => serde_json::Value::Null,
        },
        "subject.session_id" => serde_json::Value::String(operation.subject.session_id.clone()),

        // Context attributes: "context.amount", "context.currency", etc.
        other if other.starts_with("context.") => {
            let key = &other["context.".len()..];
            operation
                .context
                .attributes
                .get(key)
                .cloned()
                .unwrap_or(serde_json::Value::Null)
        }

        _ => {
            tracing::warn!(field = field, "Unknown policy field path");
            serde_json::Value::Null
        }
    }
}

/// Evaluate a single condition: compare field_value against expected value using the operator.
fn evaluate_condition(
    operator: &Operator,
    field_value: &serde_json::Value,
    expected: &serde_json::Value,
    compiled_regex: &Option<regex::Regex>,
) -> bool {
    match operator {
        Operator::Eq => field_value == expected,
        Operator::NotEq => field_value != expected,

        Operator::Gt | Operator::Lt | Operator::Gte | Operator::Lte => {
            compare_numeric(operator, field_value, expected)
        }

        Operator::Contains => {
            let haystack = value_as_str(field_value);
            let needle = value_as_str(expected);
            haystack.contains(&needle)
        }

        Operator::StartsWith => {
            let haystack = value_as_str(field_value);
            let needle = value_as_str(expected);
            haystack.starts_with(&needle)
        }

        Operator::EndsWith => {
            let haystack = value_as_str(field_value);
            let needle = value_as_str(expected);
            haystack.ends_with(&needle)
        }

        Operator::Regex => {
            let haystack = value_as_str(field_value);
            match compiled_regex {
                Some(re) => re.is_match(&haystack),
                None => false,
            }
        }

        Operator::In => {
            if let serde_json::Value::Array(arr) = expected {
                arr.contains(field_value)
            } else {
                false
            }
        }

        Operator::NotIn => {
            if let serde_json::Value::Array(arr) = expected {
                !arr.contains(field_value)
            } else {
                true
            }
        }
    }
}

/// Numeric comparison for Gt/Lt/Gte/Lte operators.
fn compare_numeric(
    operator: &Operator,
    field_value: &serde_json::Value,
    expected: &serde_json::Value,
) -> bool {
    let a = value_as_f64(field_value);
    let b = value_as_f64(expected);

    match (a, b) {
        (Some(a), Some(b)) => match operator {
            Operator::Gt => a > b,
            Operator::Lt => a < b,
            Operator::Gte => a >= b,
            Operator::Lte => a <= b,
            _ => false,
        },
        _ => false, // Non-numeric values fail numeric comparisons
    }
}

fn value_as_str(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn value_as_f64(v: &serde_json::Value) -> Option<f64> {
    match v {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn tier_as_policy_str(tier: &ResourceTier) -> &'static str {
    match tier {
        ResourceTier::Internal => "Internal",
        ResourceTier::External => "External",
        ResourceTier::CustomerFacing => "CustomerFacing",
    }
}

fn sensitivity_as_policy_str(sensitivity: &Sensitivity) -> &'static str {
    match sensitivity {
        Sensitivity::Low => "Low",
        Sensitivity::Medium => "Medium",
        Sensitivity::High => "High",
        Sensitivity::Critical => "Critical",
    }
}

/// Known top-level field prefixes for policy conditions.
/// Fields not matching these are rejected at load time to catch typos.
const KNOWN_FIELD_PREFIXES: &[&str] = &[
    "operation",
    "resource.service",
    "resource.identifier",
    "resource.tier",
    "resource.sensitivity",
    "subject.agent_id",
    "subject.tenant_id",
    "subject.session_id",
    "context.", // dynamic context attributes (context.amount, context.currency, etc.)
];

/// Validate that a condition field name is recognized.
/// Rejects unknown fields at policy load time instead of silently ignoring them at runtime.
fn validate_field_name(field: &str, rule_id: &str) -> Result<()> {
    for prefix in KNOWN_FIELD_PREFIXES {
        if field == *prefix || field.starts_with(prefix) {
            return Ok(());
        }
    }
    anyhow::bail!(
        "Unknown field '{}' in rule '{}'. Valid fields: operation, resource.{{service,identifier,tier,sensitivity}}, \
         subject.{{agent_id,tenant_id,session_id}}, context.*",
        field, rule_id,
    )
}

/// Compile a TOML rule config into a runtime PolicyRule
fn compile_rule(cfg: &PolicyRuleConfig) -> Result<PolicyRule> {
    let layer = match cfg.layer.as_str() {
        "Global" => PolicyLayer::Global,
        "Tenant" => PolicyLayer::Tenant,
        "Agent" => PolicyLayer::Agent,
        other => anyhow::bail!("Unknown policy layer: {}", other),
    };

    let mut conditions: Vec<Condition> = Vec::with_capacity(cfg.conditions.len());
    for c in &cfg.conditions {
        let operator = match c.operator.as_str() {
            "Eq" => Operator::Eq,
            "NotEq" => Operator::NotEq,
            "Gt" => Operator::Gt,
            "Lt" => Operator::Lt,
            "Gte" => Operator::Gte,
            "Lte" => Operator::Lte,
            "Contains" => Operator::Contains,
            "StartsWith" => Operator::StartsWith,
            "EndsWith" => Operator::EndsWith,
            "Regex" => Operator::Regex,
            "In" => Operator::In,
            "NotIn" => Operator::NotIn,
            other => anyhow::bail!("Unknown operator '{}' in rule {}", other, cfg.id),
        };

        let compiled_regex = if matches!(operator, Operator::Regex) {
            let pattern = value_as_str(&c.value);
            const MAX_REGEX_LEN: usize = 10_000;
            if pattern.len() > MAX_REGEX_LEN {
                anyhow::bail!(
                    "Regex pattern too long in rule {}: {} > {} bytes",
                    cfg.id,
                    pattern.len(),
                    MAX_REGEX_LEN
                );
            }
            Some(
                regex::Regex::new(&pattern)
                    .with_context(|| format!("Invalid regex in rule {}: {}", cfg.id, pattern))?,
            )
        } else {
            None
        };

        // Validate field name at compile time to catch typos early.
        // Known fields: operation, resource.*, subject.*, context.*
        validate_field_name(&c.field, &cfg.id)?;

        conditions.push(Condition {
            field: c.field.clone(),
            operator,
            value: c.value.clone(),
            compiled_regex,
        });
    }

    let decision = compile_decision(&cfg.decision)?;

    Ok(PolicyRule {
        id: cfg.id.clone(),
        priority: cfg.priority,
        layer,
        description: cfg.description.clone(),
        conditions,
        decision,
    })
}

fn compile_decision(cfg: &DecisionConfig) -> Result<EnforcementDecision> {
    match cfg.decision_type.as_str() {
        "Allow" => Ok(EnforcementDecision::Allow),

        "Delay" => Ok(EnforcementDecision::Delay {
            milliseconds: cfg.milliseconds.unwrap_or(300),
        }),

        "RequireApproval" => {
            let urgency = match cfg.urgency.as_deref() {
                Some("Immediate") => ApprovalUrgency::Immediate,
                Some("Standard") => ApprovalUrgency::Standard,
                Some("Low") | None => ApprovalUrgency::Low,
                Some(other) => {
                    tracing::warn!(urgency = other, "Unknown urgency, defaulting to Standard");
                    ApprovalUrgency::Standard
                }
            };
            Ok(EnforcementDecision::RequireApproval { urgency })
        }

        "Deny" => Ok(EnforcementDecision::Deny {
            reason: cfg
                .reason
                .clone()
                .unwrap_or_else(|| "Denied by policy".to_string()),
        }),

        "Throttle" => Ok(EnforcementDecision::Throttle {
            max_per_minute: cfg.max_per_minute.unwrap_or(60),
        }),

        "AuditOnly" => {
            let alert_level = match cfg.alert_level.as_deref() {
                Some("Info") | None => AlertLevel::Info,
                Some("Warning") => AlertLevel::Warning,
                Some("Critical") => AlertLevel::Critical,
                Some(other) => {
                    tracing::warn!(level = other, "Unknown alert level, defaulting to Info");
                    AlertLevel::Info
                }
            };
            Ok(EnforcementDecision::AuditOnly { alert_level })
        }

        other => anyhow::bail!("Unknown decision type: {}", other),
    }
}

// ─── Conflict Detection ───

/// Validate all policy rules for conflicts, contradictions, and ineffective rules.
///
/// Three categories of issues:
/// 1. **Duplicate priority**: Two rules in the same layer have the same priority.
///    First-loaded wins, which is file-system order dependent and fragile.
/// 2. **Contradictory decision**: Two rules have overlapping conditions but
///    produce opposite decisions (e.g. Allow vs Deny on same operation pattern).
/// 3. **Ineffective rule**: A lower-layer rule (Tenant/Agent) is always overridden
///    by a stricter upper-layer rule (Global). The lower rule has no effect.
pub fn validate_conflicts(
    global_rules: &[PolicyRule],
    tenant_rules: &HashMap<String, Vec<PolicyRule>>,
    agent_rules: &HashMap<String, Vec<PolicyRule>>,
) -> Vec<PolicyWarning> {
    let mut warnings = Vec::new();

    // 1. Intra-layer: duplicate priority + contradictory decisions
    check_intra_layer_conflicts(global_rules, "Global", &mut warnings);
    for (tenant_id, rules) in tenant_rules {
        check_intra_layer_conflicts(rules, &format!("Tenant({})", tenant_id), &mut warnings);
    }
    for (agent_id, rules) in agent_rules {
        check_intra_layer_conflicts(rules, &format!("Agent({})", agent_id), &mut warnings);
    }

    // 2. Cross-layer: ineffective rules (lower layer overridden by upper)
    for (tenant_id, rules) in tenant_rules {
        check_cross_layer_ineffective(
            global_rules,
            rules,
            "Global",
            &format!("Tenant({})", tenant_id),
            &mut warnings,
        );
    }
    for (agent_id, rules) in agent_rules {
        check_cross_layer_ineffective(
            global_rules,
            rules,
            "Global",
            &format!("Agent({})", agent_id),
            &mut warnings,
        );
        // Also check agent vs all tenant rules
        for (tenant_id, tenant) in tenant_rules {
            check_cross_layer_ineffective(
                tenant,
                rules,
                &format!("Tenant({})", tenant_id),
                &format!("Agent({})", agent_id),
                &mut warnings,
            );
        }
    }

    warnings
}

/// Check for duplicate priorities and contradictory decisions within a single layer.
fn check_intra_layer_conflicts(
    rules: &[PolicyRule],
    layer_name: &str,
    warnings: &mut Vec<PolicyWarning>,
) {
    for i in 0..rules.len() {
        for j in (i + 1)..rules.len() {
            let a = &rules[i];
            let b = &rules[j];

            // Check 1: Same priority
            if a.priority == b.priority {
                warnings.push(PolicyWarning {
                    severity: WarningSeverity::Warning,
                    kind: WarningKind::DuplicatePriority,
                    message: format!(
                        "Duplicate priority in {}: \"{}\" and \"{}\" both have priority {}. \
                         First loaded wins — consider adjusting priorities.",
                        layer_name, a.id, b.id, a.priority
                    ),
                });
            }

            // Check 2: Overlapping conditions with contradictory decisions
            if conditions_overlap(&a.conditions, &b.conditions)
                && decisions_contradict(&a.decision, &b.decision)
            {
                warnings.push(PolicyWarning {
                    severity: WarningSeverity::Error,
                    kind: WarningKind::ContradictoryDecision,
                    message: format!(
                        "Contradictory decisions in {}: \"{}\" ({}) and \"{}\" ({}) \
                         have overlapping conditions but opposite decisions. \
                         Priority {} vs {} — the lower-numbered priority wins.",
                        layer_name,
                        a.id,
                        decision_type_name(&a.decision),
                        b.id,
                        decision_type_name(&b.decision),
                        a.priority,
                        b.priority,
                    ),
                });
            }
        }
    }
}

/// Check if a lower-layer rule is rendered ineffective by a stricter upper-layer rule.
///
/// Specifically: if a Global rule matches the same conditions as a Tenant/Agent rule,
/// and the Global rule is strictly stricter, the lower rule can never take effect
/// (because max_strict always picks the Global decision).
fn check_cross_layer_ineffective(
    upper_rules: &[PolicyRule],
    lower_rules: &[PolicyRule],
    upper_name: &str,
    lower_name: &str,
    warnings: &mut Vec<PolicyWarning>,
) {
    for lower in lower_rules {
        for upper in upper_rules {
            // Skip if upper is less strict — the lower rule adds value
            if upper.decision.strictness() <= lower.decision.strictness() {
                continue;
            }

            // If conditions overlap and upper is strictly stricter,
            // the lower rule is ineffective
            if conditions_overlap(&upper.conditions, &lower.conditions) {
                // Special case: lower is Allow and upper is Deny/RequireApproval.
                // This is the most common "ineffective rule" pattern.
                warnings.push(PolicyWarning {
                    severity: WarningSeverity::Warning,
                    kind: WarningKind::IneffectiveRule,
                    message: format!(
                        "Ineffective rule: {} \"{}\" ({}) is always overridden by \
                         {} \"{}\" ({}). The {} rule has no effect because \
                         the stricter {} rule matches the same conditions.",
                        lower_name,
                        lower.id,
                        decision_type_name(&lower.decision),
                        upper_name,
                        upper.id,
                        decision_type_name(&upper.decision),
                        lower_name,
                        upper_name,
                    ),
                });
            }
        }
    }
}

/// Check if two condition sets overlap (could match the same operation).
///
/// Conservative approach: conditions overlap if they reference the same fields
/// with compatible values. Two empty condition sets always overlap (both are
/// unconditional). An empty condition set overlaps with everything.
fn conditions_overlap(a: &[Condition], b: &[Condition]) -> bool {
    // Unconditional rules overlap with everything
    if a.is_empty() || b.is_empty() {
        return true;
    }

    // Check if any condition in A directly matches or is subsumed by a condition in B
    // on the same field. This is a conservative heuristic — we check for:
    // 1. Same field + same operator + same value (exact duplicate)
    // 2. Same field + compatible operators (e.g. EndsWith ".read" in both)
    for ca in a {
        for cb in b {
            if ca.field == cb.field && values_could_overlap(ca, cb) {
                return true;
            }
        }
    }

    false
}

/// Check if two conditions on the same field could match the same input value.
fn values_could_overlap(a: &Condition, b: &Condition) -> bool {
    // Exact same operator and value — definitely overlaps
    if operator_name(&a.operator) == operator_name(&b.operator) && a.value == b.value {
        return true;
    }

    // StartsWith/EndsWith with matching prefixes/suffixes
    let a_str = value_as_str(&a.value);
    let b_str = value_as_str(&b.value);

    match (&a.operator, &b.operator) {
        // Both EndsWith the same string → overlap
        (Operator::EndsWith, Operator::EndsWith) if a_str == b_str => true,
        // Both StartsWith the same string → overlap
        (Operator::StartsWith, Operator::StartsWith) if a_str == b_str => true,
        // Eq vs Eq with same value → overlap
        (Operator::Eq, Operator::Eq) if a.value == b.value => true,
        // Eq vs EndsWith — if the Eq value ends with the EndsWith pattern
        (Operator::Eq, Operator::EndsWith) | (Operator::EndsWith, Operator::Eq) => {
            let eq_val = if matches!(a.operator, Operator::Eq) {
                &a_str
            } else {
                &b_str
            };
            let suffix = if matches!(a.operator, Operator::EndsWith) {
                &a_str
            } else {
                &b_str
            };
            eq_val.ends_with(suffix.as_str())
        }
        // Eq vs StartsWith — if the Eq value starts with the StartsWith pattern
        (Operator::Eq, Operator::StartsWith) | (Operator::StartsWith, Operator::Eq) => {
            let eq_val = if matches!(a.operator, Operator::Eq) {
                &a_str
            } else {
                &b_str
            };
            let prefix = if matches!(a.operator, Operator::StartsWith) {
                &a_str
            } else {
                &b_str
            };
            eq_val.starts_with(prefix.as_str())
        }
        // Contains vs Eq — if the Eq value contains the Contains pattern
        (Operator::Contains, Operator::Eq) | (Operator::Eq, Operator::Contains) => {
            let eq_val = if matches!(a.operator, Operator::Eq) {
                &a_str
            } else {
                &b_str
            };
            let needle = if matches!(a.operator, Operator::Contains) {
                &a_str
            } else {
                &b_str
            };
            eq_val.contains(needle.as_str())
        }
        // For numeric comparisons, ranges could overlap but we can't easily determine
        // without full range analysis. Be conservative: same field = potential overlap.
        (
            Operator::Gt | Operator::Gte | Operator::Lt | Operator::Lte,
            Operator::Gt | Operator::Gte | Operator::Lt | Operator::Lte,
        ) => true,
        // In/NotIn — conservative: could overlap
        (Operator::In, _) | (_, Operator::In) => true,
        // Default: different operators on same field — not enough info to determine
        _ => false,
    }
}

/// Get the decision type name for display purposes.
fn decision_type_name(decision: &EnforcementDecision) -> &'static str {
    match decision {
        EnforcementDecision::Allow => "Allow",
        EnforcementDecision::Delay { .. } => "Delay",
        EnforcementDecision::RequireApproval { .. } => "RequireApproval",
        EnforcementDecision::Deny { .. } => "Deny",
        EnforcementDecision::Throttle { .. } => "Throttle",
        EnforcementDecision::AuditOnly { .. } => "AuditOnly",
    }
}

/// Get operator name for comparison purposes.
fn operator_name(op: &Operator) -> &'static str {
    match op {
        Operator::Eq => "Eq",
        Operator::NotEq => "NotEq",
        Operator::Gt => "Gt",
        Operator::Lt => "Lt",
        Operator::Gte => "Gte",
        Operator::Lte => "Lte",
        Operator::Contains => "Contains",
        Operator::StartsWith => "StartsWith",
        Operator::EndsWith => "EndsWith",
        Operator::Regex => "Regex",
        Operator::In => "In",
        Operator::NotIn => "NotIn",
    }
}

/// Check if two decisions contradict each other.
/// Contradiction = one allows traffic and the other blocks it.
fn decisions_contradict(a: &EnforcementDecision, b: &EnforcementDecision) -> bool {
    let a_allows = matches!(
        a,
        EnforcementDecision::Allow | EnforcementDecision::AuditOnly { .. }
    );
    let b_allows = matches!(
        b,
        EnforcementDecision::Allow | EnforcementDecision::AuditOnly { .. }
    );
    let a_blocks = matches!(
        a,
        EnforcementDecision::Deny { .. } | EnforcementDecision::RequireApproval { .. }
    );
    let b_blocks = matches!(
        b,
        EnforcementDecision::Deny { .. } | EnforcementDecision::RequireApproval { .. }
    );

    (a_allows && b_blocks) || (a_blocks && b_allows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_operation(op: &str, sensitivity: Sensitivity, tier: ResourceTier) -> OperationMetadata {
        OperationMetadata {
            operation: op.to_string(),
            resource: ResourceDescriptor {
                service: "test".to_string(),
                identifier: None,
                tier,
                sensitivity,
            },
            subject: SubjectDescriptor {
                agent_id: "test-agent".to_string(),
                tenant_id: None,
                session_id: "test-session".to_string(),
            },
            context: OperationContext {
                attributes: HashMap::new(),
            },
            payload: PayloadDescriptor::default(),
        }
    }

    #[test]
    fn test_starts_with_condition() {
        let cond = Condition {
            field: "operation".to_string(),
            operator: Operator::StartsWith,
            value: serde_json::Value::String("gvm.payment".to_string()),
            compiled_regex: None,
        };

        let op = make_operation(
            "gvm.payment.charge",
            Sensitivity::High,
            ResourceTier::External,
        );
        let field_val = resolve_field(&cond.field, &op);
        assert!(evaluate_condition(
            &cond.operator,
            &field_val,
            &cond.value,
            &cond.compiled_regex
        ));
    }

    #[test]
    fn test_ends_with_condition() {
        let cond = Condition {
            field: "operation".to_string(),
            operator: Operator::EndsWith,
            value: serde_json::Value::String(".read".to_string()),
            compiled_regex: None,
        };

        let op = make_operation("gvm.storage.read", Sensitivity::Low, ResourceTier::Internal);
        let field_val = resolve_field(&cond.field, &op);
        assert!(evaluate_condition(
            &cond.operator,
            &field_val,
            &cond.value,
            &cond.compiled_regex
        ));
    }

    #[test]
    fn test_numeric_gt_condition() {
        let cond = Condition {
            field: "context.amount".to_string(),
            operator: Operator::Gt,
            value: serde_json::json!(500),
            compiled_regex: None,
        };

        let mut op = make_operation(
            "gvm.payment.refund",
            Sensitivity::High,
            ResourceTier::External,
        );
        op.context
            .attributes
            .insert("amount".to_string(), serde_json::json!(1000));

        let field_val = resolve_field(&cond.field, &op);
        assert!(evaluate_condition(
            &cond.operator,
            &field_val,
            &cond.value,
            &cond.compiled_regex
        ));
    }

    // ─── Conflict Detection Tests ───

    #[test]
    fn test_duplicate_priority_detected() {
        let rules = vec![
            PolicyRule {
                id: "rule-a".to_string(),
                priority: 10,
                layer: PolicyLayer::Global,
                description: "Allow reads".to_string(),
                conditions: vec![Condition {
                    field: "operation".to_string(),
                    operator: Operator::EndsWith,
                    value: serde_json::Value::String(".read".to_string()),
                    compiled_regex: None,
                }],
                decision: EnforcementDecision::Allow,
            },
            PolicyRule {
                id: "rule-b".to_string(),
                priority: 10,
                layer: PolicyLayer::Global,
                description: "Deny reads".to_string(),
                conditions: vec![Condition {
                    field: "operation".to_string(),
                    operator: Operator::EndsWith,
                    value: serde_json::Value::String(".read".to_string()),
                    compiled_regex: None,
                }],
                decision: EnforcementDecision::Deny {
                    reason: "Suspended".to_string(),
                },
            },
        ];

        let warnings = validate_conflicts(&rules, &HashMap::new(), &HashMap::new());
        assert!(
            warnings
                .iter()
                .any(|w| w.kind == WarningKind::DuplicatePriority),
            "should detect duplicate priority"
        );
    }

    #[test]
    fn test_contradictory_decisions_detected() {
        let rules = vec![
            PolicyRule {
                id: "allow-reads".to_string(),
                priority: 10,
                layer: PolicyLayer::Global,
                description: "Allow reads".to_string(),
                conditions: vec![Condition {
                    field: "operation".to_string(),
                    operator: Operator::EndsWith,
                    value: serde_json::Value::String(".read".to_string()),
                    compiled_regex: None,
                }],
                decision: EnforcementDecision::Allow,
            },
            PolicyRule {
                id: "deny-reads".to_string(),
                priority: 20,
                layer: PolicyLayer::Global,
                description: "Deny reads".to_string(),
                conditions: vec![Condition {
                    field: "operation".to_string(),
                    operator: Operator::EndsWith,
                    value: serde_json::Value::String(".read".to_string()),
                    compiled_regex: None,
                }],
                decision: EnforcementDecision::Deny {
                    reason: "Suspended".to_string(),
                },
            },
        ];

        let warnings = validate_conflicts(&rules, &HashMap::new(), &HashMap::new());
        assert!(
            warnings
                .iter()
                .any(|w| w.kind == WarningKind::ContradictoryDecision),
            "should detect contradictory decisions on same conditions"
        );
    }

    #[test]
    fn test_ineffective_tenant_rule_detected() {
        let global = vec![PolicyRule {
            id: "global-deny-payment".to_string(),
            priority: 1,
            layer: PolicyLayer::Global,
            description: "Deny all payments".to_string(),
            conditions: vec![Condition {
                field: "operation".to_string(),
                operator: Operator::StartsWith,
                value: serde_json::Value::String("gvm.payment".to_string()),
                compiled_regex: None,
            }],
            decision: EnforcementDecision::Deny {
                reason: "Payments disabled".to_string(),
            },
        }];

        let mut tenant_rules = HashMap::new();
        tenant_rules.insert(
            "acme".to_string(),
            vec![PolicyRule {
                id: "tenant-allow-payment".to_string(),
                priority: 1,
                layer: PolicyLayer::Tenant,
                description: "Allow payments for acme".to_string(),
                conditions: vec![Condition {
                    field: "operation".to_string(),
                    operator: Operator::Eq,
                    value: serde_json::Value::String("gvm.payment.charge".to_string()),
                    compiled_regex: None,
                }],
                decision: EnforcementDecision::Allow,
            }],
        );

        let warnings = validate_conflicts(&global, &tenant_rules, &HashMap::new());
        assert!(
            warnings
                .iter()
                .any(|w| w.kind == WarningKind::IneffectiveRule),
            "should detect tenant Allow overridden by global Deny"
        );
    }

    #[test]
    fn test_no_conflict_for_non_overlapping_rules() {
        let rules = vec![
            PolicyRule {
                id: "allow-reads".to_string(),
                priority: 10,
                layer: PolicyLayer::Global,
                description: "Allow reads".to_string(),
                conditions: vec![Condition {
                    field: "operation".to_string(),
                    operator: Operator::EndsWith,
                    value: serde_json::Value::String(".read".to_string()),
                    compiled_regex: None,
                }],
                decision: EnforcementDecision::Allow,
            },
            PolicyRule {
                id: "deny-deletes".to_string(),
                priority: 20,
                layer: PolicyLayer::Global,
                description: "Deny deletes".to_string(),
                conditions: vec![Condition {
                    field: "operation".to_string(),
                    operator: Operator::EndsWith,
                    value: serde_json::Value::String(".delete".to_string()),
                    compiled_regex: None,
                }],
                decision: EnforcementDecision::Deny {
                    reason: "Deletes forbidden".to_string(),
                },
            },
        ];

        let warnings = validate_conflicts(&rules, &HashMap::new(), &HashMap::new());
        assert!(
            warnings.is_empty(),
            "non-overlapping rules should not produce warnings, got: {:?}",
            warnings
        );
    }

    #[test]
    fn test_unconditional_rule_overlaps_everything() {
        let rules = vec![
            PolicyRule {
                id: "catch-all-allow".to_string(),
                priority: 100,
                layer: PolicyLayer::Global,
                description: "Allow all".to_string(),
                conditions: vec![], // unconditional
                decision: EnforcementDecision::Allow,
            },
            PolicyRule {
                id: "deny-specific".to_string(),
                priority: 1,
                layer: PolicyLayer::Global,
                description: "Deny specific".to_string(),
                conditions: vec![Condition {
                    field: "operation".to_string(),
                    operator: Operator::Eq,
                    value: serde_json::Value::String("gvm.storage.delete".to_string()),
                    compiled_regex: None,
                }],
                decision: EnforcementDecision::Deny {
                    reason: "Blocked".to_string(),
                },
            },
        ];

        let warnings = validate_conflicts(&rules, &HashMap::new(), &HashMap::new());
        // Unconditional catch-all (Allow) + specific Deny = contradictory
        assert!(
            warnings
                .iter()
                .any(|w| w.kind == WarningKind::ContradictoryDecision),
            "unconditional Allow rule should contradict specific Deny"
        );
    }

    #[test]
    fn test_eq_vs_startswith_overlap() {
        let rules = vec![
            PolicyRule {
                id: "allow-charge".to_string(),
                priority: 10,
                layer: PolicyLayer::Global,
                description: "Allow charge".to_string(),
                conditions: vec![Condition {
                    field: "operation".to_string(),
                    operator: Operator::Eq,
                    value: serde_json::Value::String("gvm.payment.charge".to_string()),
                    compiled_regex: None,
                }],
                decision: EnforcementDecision::Allow,
            },
            PolicyRule {
                id: "deny-payment".to_string(),
                priority: 20,
                layer: PolicyLayer::Global,
                description: "Deny payments".to_string(),
                conditions: vec![Condition {
                    field: "operation".to_string(),
                    operator: Operator::StartsWith,
                    value: serde_json::Value::String("gvm.payment".to_string()),
                    compiled_regex: None,
                }],
                decision: EnforcementDecision::Deny {
                    reason: "Payments blocked".to_string(),
                },
            },
        ];

        let warnings = validate_conflicts(&rules, &HashMap::new(), &HashMap::new());
        assert!(
            warnings
                .iter()
                .any(|w| w.kind == WarningKind::ContradictoryDecision),
            "Eq 'gvm.payment.charge' should overlap with StartsWith 'gvm.payment'"
        );
    }

    // ─── Existing Tests ───

    #[test]
    fn test_deny_overrides_all() {
        let rules = vec![
            PolicyRule {
                id: "allow-read".to_string(),
                priority: 100,
                layer: PolicyLayer::Global,
                description: "Allow reads".to_string(),
                conditions: vec![Condition {
                    field: "operation".to_string(),
                    operator: Operator::EndsWith,
                    value: serde_json::Value::String(".read".to_string()),
                    compiled_regex: None,
                }],
                decision: EnforcementDecision::Allow,
            },
            PolicyRule {
                id: "deny-critical-delete".to_string(),
                priority: 1,
                layer: PolicyLayer::Global,
                description: "Deny critical delete".to_string(),
                conditions: vec![
                    Condition {
                        field: "operation".to_string(),
                        operator: Operator::Eq,
                        value: serde_json::Value::String("gvm.storage.delete".to_string()),
                        compiled_regex: None,
                    },
                    Condition {
                        field: "resource.sensitivity".to_string(),
                        operator: Operator::Eq,
                        value: serde_json::Value::String("Critical".to_string()),
                        compiled_regex: None,
                    },
                ],
                decision: EnforcementDecision::Deny {
                    reason: "Critical data deletion forbidden".to_string(),
                },
            },
        ];

        let engine = PolicyEngine {
            global_rules: rules,
            tenant_rules: HashMap::new(),
            agent_rules: HashMap::new(),
        };

        let op = make_operation(
            "gvm.storage.delete",
            Sensitivity::Critical,
            ResourceTier::Internal,
        );
        let (decision, rule_id) = engine.evaluate(&op);
        assert!(matches!(decision, EnforcementDecision::Deny { .. }));
        assert_eq!(
            rule_id.expect("deny rule must produce matched_rule_id"),
            "deny-critical-delete"
        );
    }
}
