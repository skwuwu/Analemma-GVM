use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

// ─── Operation Registry (PART 1.7) ───

/// Core operation definition from registry
#[derive(Deserialize, Clone, Debug)]
pub struct CoreOperation {
    pub name: String,
    pub description: String,
    pub version: u32,
    pub status: String,
    pub default_ic: u8,
    pub required_context: Vec<String>,
    pub semantic_contract: Option<String>,
}

/// Custom operation definition from registry
#[derive(Deserialize, Clone, Debug)]
pub struct CustomOperation {
    pub name: String,
    pub description: String,
    pub vendor: String,
    pub version: u32,
    pub status: String,
    pub default_ic: u8,
    pub required_context: Vec<String>,
    /// Maps to a Core operation for automatic policy inheritance.
    /// null means no mapping — only custom-specific policies apply.
    pub maps_to: Option<String>,
}

#[derive(Deserialize, Debug)]
struct RegistryFile {
    #[serde(default)]
    core: Vec<CoreOperation>,
    #[serde(default)]
    custom: Vec<CustomOperation>,
}

/// Operation Registry: schema-backed operation definitions with validation.
///
/// Responsibilities:
/// - Validate operation names and structure at startup
/// - Enforce maps_to safety (no IC downgrade)
/// - Provide operation metadata lookup for policy engine
#[derive(Debug)]
pub struct OperationRegistry {
    core_ops: HashMap<String, CoreOperation>,
    custom_ops: HashMap<String, CustomOperation>,
}

impl OperationRegistry {
    /// Load and validate the operation registry from TOML.
    /// Fail-Close: if validation fails, the proxy must not start.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read registry: {}", path.display()))?;
        let file: RegistryFile = toml::from_str(&content)
            .with_context(|| format!("Failed to parse registry: {}", path.display()))?;

        let mut core_ops = HashMap::new();
        for op in &file.core {
            Self::validate_core_name(&op.name)?;
            Self::validate_ic(op.default_ic)?;
            if core_ops.contains_key(&op.name) {
                anyhow::bail!("Duplicate core operation: '{}'", op.name);
            }
            core_ops.insert(op.name.clone(), op.clone());
        }

        let mut custom_ops = HashMap::new();
        for op in &file.custom {
            Self::validate_custom_name(&op.name, &op.vendor)?;
            Self::validate_ic(op.default_ic)?;
            if custom_ops.contains_key(&op.name) {
                anyhow::bail!("Duplicate custom operation: '{}'", op.name);
            }
            custom_ops.insert(op.name.clone(), op.clone());
        }

        // Validate maps_to mappings (Fail-Close at startup)
        for custom in custom_ops.values() {
            if let Some(ref maps_to) = custom.maps_to {
                let core = core_ops.get(maps_to).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Custom operation '{}' maps_to '{}' which does not exist in core registry",
                        custom.name,
                        maps_to
                    )
                })?;

                Self::validate_mapping(custom, core)?;
            }
        }

        tracing::info!(
            core = core_ops.len(),
            custom = custom_ops.len(),
            "Operation registry loaded and validated"
        );

        Ok(Self {
            core_ops,
            custom_ops,
        })
    }

    /// Validate maps_to safety: custom IC must not exceed core IC.
    /// This prevents policy weakening through mapping.
    ///
    /// Example blocked: custom.banking.transfer (IC-3) → gvm.storage.read (IC-1)
    /// This would allow a high-risk operation to inherit low-risk policies.
    fn validate_mapping(custom: &CustomOperation, core: &CoreOperation) -> Result<()> {
        if core.default_ic < custom.default_ic {
            anyhow::bail!(
                "Unsafe mapping: '{}' (IC-{}) → '{}' (IC-{}). \
                 Custom IC exceeds core IC — policy would be weakened. \
                 Core IC must be >= custom IC.",
                custom.name,
                custom.default_ic,
                core.name,
                core.default_ic
            );
        }
        Ok(())
    }

    /// Core operation names must be 3-segment: gvm.{category}.{action}
    fn validate_core_name(name: &str) -> Result<()> {
        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() != 3 || parts[0] != "gvm" {
            anyhow::bail!(
                "Invalid core operation name '{}': must be gvm.{{category}}.{{action}} (3 segments)",
                name
            );
        }
        Self::validate_segments(&parts, name)?;
        Ok(())
    }

    /// Custom operation names must be 4-segment: custom.{vendor}.{domain}.{action}
    fn validate_custom_name(name: &str, vendor: &str) -> Result<()> {
        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() != 4 || parts[0] != "custom" {
            anyhow::bail!(
                "Invalid custom operation name '{}': must be custom.{{vendor}}.{{domain}}.{{action}} (4 segments)",
                name
            );
        }
        Self::validate_segments(&parts, name)?;
        if parts[1] != vendor {
            anyhow::bail!(
                "Vendor mismatch in '{}': name segment '{}' != declared vendor '{}'",
                name,
                parts[1],
                vendor
            );
        }
        Ok(())
    }

    /// Validate that each segment is non-empty and contains only alphanumeric + underscore.
    fn validate_segments(parts: &[&str], name: &str) -> Result<()> {
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                anyhow::bail!("Empty segment at position {} in '{}'", i, name);
            }
            if !part.chars().all(|c| c.is_alphanumeric() || c == '_') {
                anyhow::bail!(
                    "Invalid characters in segment '{}' of '{}' (only alphanumeric and underscore allowed)",
                    part,
                    name
                );
            }
        }
        Ok(())
    }

    fn validate_ic(ic: u8) -> Result<()> {
        if !(1..=3).contains(&ic) {
            anyhow::bail!("Invalid default_ic: {}. Must be 1, 2, or 3.", ic);
        }
        Ok(())
    }

    /// Look up an operation by name. Checks custom first, then core.
    pub fn lookup(&self, name: &str) -> Option<OperationInfo> {
        if let Some(custom) = self.custom_ops.get(name) {
            let mapped_core = custom
                .maps_to
                .as_ref()
                .and_then(|m| self.core_ops.get(m));
            return Some(OperationInfo {
                name: &custom.name,
                default_ic: custom.default_ic,
                required_context: &custom.required_context,
                mapped_core: mapped_core.map(|c| c.name.as_str()),
            });
        }

        if let Some(core) = self.core_ops.get(name) {
            return Some(OperationInfo {
                name: &core.name,
                default_ic: core.default_ic,
                required_context: &core.required_context,
                mapped_core: None,
            });
        }

        None
    }

    /// Get the effective core operation name for policy lookup.
    /// For custom operations with maps_to, returns the core operation name.
    /// For core operations, returns the operation name itself.
    pub fn effective_core_operation(&self, name: &str) -> Option<String> {
        if let Some(custom) = self.custom_ops.get(name) {
            return Some(
                custom
                    .maps_to
                    .clone()
                    .unwrap_or_else(|| name.to_string()),
            );
        }
        if self.core_ops.contains_key(name) {
            return Some(name.to_string());
        }
        None
    }

    /// Number of core operations registered.
    pub fn core_count(&self) -> usize {
        self.core_ops.len()
    }

    /// Number of custom operations registered.
    pub fn custom_count(&self) -> usize {
        self.custom_ops.len()
    }
}

/// Read-only view of operation metadata for consumers.
#[derive(Debug)]
pub struct OperationInfo<'a> {
    pub name: &'a str,
    pub default_ic: u8,
    pub required_context: &'a [String],
    pub mapped_core: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_toml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("temp file creation must succeed");
        f.write_all(content.as_bytes()).expect("writing TOML to temp file must succeed");
        f
    }

    #[test]
    fn test_valid_registry_loads() {
        let toml = r#"
[[core]]
name = "gvm.messaging.send"
description = "Send message"
version = 1
status = "stable"
default_ic = 2
required_context = ["recipient"]
semantic_contract = "Send message to recipient"

[[custom]]
name = "custom.acme.crm.email"
description = "Send CRM email"
vendor = "acme"
version = 1
status = "stable"
default_ic = 2
required_context = ["recipient"]
maps_to = "gvm.messaging.send"
"#;
        let f = write_temp_toml(toml);
        let registry = OperationRegistry::load(f.path()).expect("valid registry TOML must load");

        assert!(registry.lookup("gvm.messaging.send").is_some());
        assert!(registry.lookup("custom.acme.crm.email").is_some());
        assert_eq!(
            registry.effective_core_operation("custom.acme.crm.email"),
            Some("gvm.messaging.send".to_string())
        );
    }

    #[test]
    fn test_unsafe_mapping_rejected() {
        let toml = r#"
[[core]]
name = "gvm.storage.read"
description = "Read storage"
version = 1
status = "stable"
default_ic = 1
required_context = []

[[custom]]
name = "custom.acme.banking.transfer"
description = "Wire transfer"
vendor = "acme"
version = 1
status = "stable"
default_ic = 3
required_context = ["amount"]
maps_to = "gvm.storage.read"
"#;
        let f = write_temp_toml(toml);
        let result = OperationRegistry::load(f.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Unsafe mapping"));
    }

    #[test]
    fn test_invalid_core_name_rejected() {
        let toml = r#"
[[core]]
name = "invalid.two.segments.four"
description = "Bad name"
version = 1
status = "stable"
default_ic = 1
required_context = []
"#;
        let f = write_temp_toml(toml);
        let result = OperationRegistry::load(f.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_vendor_mismatch_rejected() {
        let toml = r#"
[[custom]]
name = "custom.acme.banking.transfer"
description = "Transfer"
vendor = "notacme"
version = 1
status = "stable"
default_ic = 3
required_context = []
"#;
        let f = write_temp_toml(toml);
        let result = OperationRegistry::load(f.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Vendor mismatch"));
    }
}
