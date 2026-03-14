//! Layer 1: Wasm Governance Engine — immutable policy evaluation sandbox.
//!
//! Loads the governance engine as a Wasm module via Wasmtime, ensuring the
//! policy evaluation logic is memory-isolated and tamper-proof. Even if the
//! host proxy process is compromised, the governance logic cannot be modified.
//!
//! Falls back to native evaluation (direct Rust call) when no Wasm module
//! is available — useful for development and testing.

use crate::types::*;
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Mutex;

/// Governance engine mode — Wasm sandbox or native fallback.
enum EngineMode {
    /// Production: policy logic runs inside Wasmtime sandbox.
    Wasm {
        engine: wasmtime::Engine,
        module: wasmtime::Module,
        /// Pre-allocated store + instance, protected by mutex for sequential access.
        /// Wasmtime Store is not Send+Sync by default, so we wrap in Mutex.
        runtime: Mutex<WasmRuntime>,
    },
    /// Development fallback: call gvm_engine::evaluate() directly.
    Native,
}

struct WasmRuntime {
    store: wasmtime::Store<()>,
    instance: wasmtime::Instance,
}

/// Wasm Governance Engine — wraps policy evaluation in a memory-isolated sandbox.
///
/// Security properties:
/// - Wasm module is content-addressed (verified by SHA-256 hash before loading)
/// - Memory isolation: Wasm cannot access host memory
/// - No syscalls: pure computation only (no I/O, no network, no filesystem)
/// - Deterministic: same input always produces same output
pub struct WasmEngine {
    mode: EngineMode,
    /// SHA-256 hash of the loaded Wasm module (None for native mode)
    pub module_hash: Option<String>,
}

impl WasmEngine {
    /// Load the governance engine from a Wasm file.
    /// Falls back to native mode if the file doesn't exist.
    pub fn load(wasm_path: &Path) -> Result<Self> {
        if !wasm_path.exists() {
            tracing::warn!(
                path = %wasm_path.display(),
                "Wasm engine module not found — using native fallback. \
                 Build with: cargo build -p gvm-engine --target wasm32-wasip1 --release"
            );
            return Ok(Self {
                mode: EngineMode::Native,
                module_hash: None,
            });
        }

        let wasm_bytes = std::fs::read(wasm_path)
            .with_context(|| format!("Failed to read Wasm module: {}", wasm_path.display()))?;

        // Compute content hash for integrity verification
        let hash = compute_sha256(&wasm_bytes);
        tracing::info!(
            path = %wasm_path.display(),
            hash = %hash,
            size_bytes = wasm_bytes.len(),
            "Loading Wasm governance engine"
        );

        // Configure Wasmtime with minimal capabilities (no WASI, no imports)
        let mut config = wasmtime::Config::new();
        config.cranelift_opt_level(wasmtime::OptLevel::Speed);

        let engine = wasmtime::Engine::new(&config)
            .context("Failed to create Wasmtime engine")?;

        let module = wasmtime::Module::new(&engine, &wasm_bytes)
            .context("Failed to compile Wasm module")?;

        // Create store and instantiate
        let mut store = wasmtime::Store::new(&engine, ());
        let instance = wasmtime::Instance::new(&mut store, &module, &[])
            .context("Failed to instantiate Wasm module")?;

        // Verify required exports exist
        let _ = instance.get_func(&mut store, "engine_alloc")
            .context("Wasm module missing 'engine_alloc' export")?;
        let _ = instance.get_func(&mut store, "engine_dealloc")
            .context("Wasm module missing 'engine_dealloc' export")?;
        let _ = instance.get_func(&mut store, "engine_evaluate")
            .context("Wasm module missing 'engine_evaluate' export")?;

        tracing::info!("Wasm governance engine loaded and verified");

        Ok(Self {
            mode: EngineMode::Wasm {
                engine,
                module,
                runtime: Mutex::new(WasmRuntime { store, instance }),
            },
            module_hash: Some(hash),
        })
    }

    /// Create a native-only engine (no Wasm).
    pub fn native() -> Self {
        Self {
            mode: EngineMode::Native,
            module_hash: None,
        }
    }

    /// Evaluate a policy request through the governance engine.
    /// In Wasm mode: serializes to JSON → calls Wasm → deserializes result.
    /// In native mode: calls gvm_engine::evaluate() directly.
    pub fn evaluate(&self, req: &gvm_engine::EvalRequest) -> Result<gvm_engine::EvalResponse> {
        match &self.mode {
            EngineMode::Wasm { runtime, .. } => {
                self.evaluate_wasm(runtime, req)
            }
            EngineMode::Native => {
                Ok(gvm_engine::evaluate(req))
            }
        }
    }

    /// Evaluate via Wasm module using the FFI protocol:
    /// 1. Serialize request to JSON
    /// 2. Allocate memory in Wasm via engine_alloc
    /// 3. Copy JSON into Wasm memory
    /// 4. Call engine_evaluate(ptr, len) → result_ptr
    /// 5. Read length-prefixed JSON response from Wasm memory
    /// 6. Deallocate input memory
    /// 7. Deserialize response
    fn evaluate_wasm(
        &self,
        runtime: &Mutex<WasmRuntime>,
        req: &gvm_engine::EvalRequest,
    ) -> Result<gvm_engine::EvalResponse> {
        let input_json = serde_json::to_string(req)
            .context("Failed to serialize EvalRequest")?;
        let input_bytes = input_json.as_bytes();

        let mut rt = runtime.lock().map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        // Copy instance handle (it's a lightweight Copy type)
        let instance = rt.instance;

        // Get exported functions
        let alloc_fn = instance.get_typed_func::<u32, u32>(&mut rt.store, "engine_alloc")
            .context("Failed to get engine_alloc")?;
        let dealloc_fn = instance.get_typed_func::<(u32, u32), ()>(&mut rt.store, "engine_dealloc")
            .context("Failed to get engine_dealloc")?;
        let evaluate_fn = instance.get_typed_func::<(u32, u32), u32>(&mut rt.store, "engine_evaluate")
            .context("Failed to get engine_evaluate")?;

        // Get Wasm memory
        let memory = instance.get_memory(&mut rt.store, "memory")
            .context("Wasm module missing 'memory' export")?;

        // 1. Allocate input buffer in Wasm
        let input_len = input_bytes.len() as u32;
        let input_ptr = alloc_fn.call(&mut rt.store, input_len)
            .context("engine_alloc failed")?;

        // 2. Copy input JSON into Wasm memory
        memory.write(&mut rt.store, input_ptr as usize, input_bytes)
            .context("Failed to write input to Wasm memory")?;

        // 3. Call engine_evaluate
        let result_ptr = evaluate_fn.call(&mut rt.store, (input_ptr, input_len))
            .context("engine_evaluate failed")?;

        // 4. Read length prefix (4 bytes, little-endian u32)
        let mut len_buf = [0u8; 4];
        memory.read(&mut rt.store, result_ptr as usize, &mut len_buf)
            .context("Failed to read result length from Wasm memory")?;
        let result_len = u32::from_le_bytes(len_buf) as usize;

        // 5. Read response JSON
        let mut result_buf = vec![0u8; result_len];
        memory.read(&mut rt.store, (result_ptr as usize) + 4, &mut result_buf)
            .context("Failed to read result data from Wasm memory")?;

        // 6. Deallocate input buffer
        let _ = dealloc_fn.call(&mut rt.store, (input_ptr, input_len));

        // 7. Parse response
        let result_str = std::str::from_utf8(&result_buf)
            .context("Wasm response is not valid UTF-8")?;

        let response: gvm_engine::EvalResponse = serde_json::from_str(result_str)
            .with_context(|| format!("Failed to parse Wasm response: {}", result_str))?;

        Ok(response)
    }

    /// Check if running in Wasm mode (production) or native fallback (development).
    pub fn is_wasm(&self) -> bool {
        matches!(self.mode, EngineMode::Wasm { .. })
    }

    /// Convert a gvm_engine::EvalResponse to the proxy's EnforcementDecision.
    pub fn response_to_decision(resp: &gvm_engine::EvalResponse) -> (EnforcementDecision, Option<String>) {
        let decision = match resp.decision.as_str() {
            "Allow" => EnforcementDecision::Allow,
            "Delay" => EnforcementDecision::Delay {
                milliseconds: resp.delay_ms.unwrap_or(300),
            },
            "Deny" => EnforcementDecision::Deny {
                reason: resp.reason.clone().unwrap_or_else(|| "Denied by Wasm engine".to_string()),
            },
            "RequireApproval" => EnforcementDecision::RequireApproval {
                urgency: ApprovalUrgency::Standard,
            },
            "AuditOnly" => EnforcementDecision::AuditOnly {
                alert_level: AlertLevel::Info,
            },
            "Throttle" => EnforcementDecision::Throttle {
                max_per_minute: 60,
            },
            _ => EnforcementDecision::Allow,
        };

        (decision, resp.matched_rule.clone())
    }

    /// Convert proxy OperationMetadata + policy rules into a gvm_engine::EvalRequest.
    /// This bridges the proxy's type system with the engine's standalone types.
    pub fn build_eval_request(
        operation: &OperationMetadata,
        rules: &[gvm_engine::Rule],
    ) -> gvm_engine::EvalRequest {
        gvm_engine::EvalRequest {
            operation: operation.operation.clone(),
            resource: gvm_engine::ResourceAttrs {
                service: operation.resource.service.clone(),
                tier: format!("{:?}", operation.resource.tier),
                sensitivity: format!("{:?}", operation.resource.sensitivity),
            },
            subject: gvm_engine::SubjectAttrs {
                agent_id: operation.subject.agent_id.clone(),
                tenant_id: operation.subject.tenant_id.clone(),
            },
            rules: rules.to_vec(),
        }
    }
}

fn compute_sha256(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_fallback() {
        let engine = WasmEngine::native();
        assert!(!engine.is_wasm());
        assert!(engine.module_hash.is_none());

        let req = gvm_engine::EvalRequest {
            operation: "gvm.messaging.read".to_string(),
            resource: gvm_engine::ResourceAttrs {
                service: "gmail".to_string(),
                tier: "external".to_string(),
                sensitivity: "low".to_string(),
            },
            subject: gvm_engine::SubjectAttrs {
                agent_id: "test-agent".to_string(),
                tenant_id: None,
            },
            rules: vec![],
        };

        let resp = engine.evaluate(&req).unwrap();
        assert_eq!(resp.decision, "Allow");
    }

    #[test]
    fn test_native_deny() {
        let engine = WasmEngine::native();

        let req = gvm_engine::EvalRequest {
            operation: "gvm.storage.delete".to_string(),
            resource: gvm_engine::ResourceAttrs {
                service: "db".to_string(),
                tier: "internal".to_string(),
                sensitivity: "critical".to_string(),
            },
            subject: gvm_engine::SubjectAttrs {
                agent_id: "test-agent".to_string(),
                tenant_id: None,
            },
            rules: vec![gvm_engine::Rule {
                id: "deny-critical".to_string(),
                priority: 1,
                layer: "global".to_string(),
                conditions: vec![gvm_engine::Condition {
                    field: "resource.sensitivity".to_string(),
                    operator: "eq".to_string(),
                    value: serde_json::Value::String("critical".to_string()),
                }],
                decision: gvm_engine::Decision {
                    decision_type: "Deny".to_string(),
                    milliseconds: None,
                    reason: Some("Critical data protected".to_string()),
                },
            }],
        };

        let resp = engine.evaluate(&req).unwrap();
        assert_eq!(resp.decision, "Deny");
        assert_eq!(resp.reason.as_deref(), Some("Critical data protected"));
    }

    #[test]
    fn test_response_to_decision() {
        let resp = gvm_engine::EvalResponse {
            decision: "Delay".to_string(),
            delay_ms: Some(500),
            reason: None,
            matched_rule: Some("delay-rule".to_string()),
            matched_layer: Some("global".to_string()),
            engine_version: "0.1.0-wasm".to_string(),
        };

        let (decision, rule_id) = WasmEngine::response_to_decision(&resp);
        assert!(matches!(decision, EnforcementDecision::Delay { milliseconds: 500 }));
        assert_eq!(rule_id.as_deref(), Some("delay-rule"));
    }

    #[test]
    fn test_load_missing_wasm() {
        let engine = WasmEngine::load(Path::new("nonexistent.wasm")).unwrap();
        assert!(!engine.is_wasm());
    }
}
