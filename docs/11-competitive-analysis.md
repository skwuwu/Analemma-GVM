# Competitive Positioning

> Where GVM fits in the AI safety landscape.

---

## The Question You'll Be Asked

**"Why not just use the LLM provider's built-in safety features?"**

Every LLM provider ships safety layers: Anthropic's usage policies, OpenAI's moderation API, Google's safety filters. These are necessary but insufficient for agent governance. Here's why:

| | LLM Provider Safety | Prompt Guardrails (Lakera, Prompt Armor) | **GVM** |
|---|---|---|---|
| **What it controls** | Model output content | Model input/output content | **Agent actions** (HTTP calls) |
| **Threat model** | "Don't say harmful things" | "Don't let injected prompts bypass filters" | **"Don't let the agent do harmful things"** |
| **Enforcement point** | Inside the model | Before/after model inference | **Between agent and external APIs** |
| **Scope** | Single LLM call | Single LLM call | **Entire agent session** (multi-step) |
| **Audit** | Provider logs (you may not own) | Prompt/response logs | **Durable WAL with Merkle chain** (you own) |
| **Provider lock-in** | Yes (per-provider) | Mostly (prompt-format dependent) | **No** (HTTP proxy — works with any provider) |

### The Gap

LLM safety says: *"The model shouldn't generate a wire transfer instruction."*

But a prompt-injected agent doesn't need the model to say "transfer money." It needs the model to emit an HTTP request to `api.bank.com/transfer`. The model's safety training may not flag this as harmful — it's just an API call. The agent framework executes it.

**GVM intercepts the action, not the thought.** It sits at the network layer where the agent's HTTP requests become observable, auditable, and enforceable — regardless of which LLM, framework, or language the agent uses.

---

## Competitive Landscape

### Prompt-Level Guards (Lakera, Prompt Armor, Rebuff)

These products detect and block prompt injection at the input/output boundary of LLM calls. They're complementary to GVM, not competitive:

- **What they do well**: Detect injection patterns, PII leakage, jailbreak attempts in prompts and responses
- **What they don't do**: Control what the agent *does* after receiving a response. An agent that passes all prompt filters can still call `DELETE /production/database` if the tool is available
- **Relationship to GVM**: Use both. Prompt guards protect the LLM call. GVM protects the API calls the agent makes as a result

### LLM Provider Built-in Safety (Anthropic, OpenAI, Google)

Provider safety filters are the first line of defense but have structural limitations:

- **Provider-specific**: Each provider's safety works differently. Multi-provider agents (fallback chains, routing) need per-provider configuration
- **Output-focused**: Safety filters evaluate what the model *says*, not what the agent *does*. Tool calls may bypass content filters entirely
- **No action audit**: Provider logs record prompts and completions, not the downstream API calls those completions trigger
- **You don't own the audit trail**: Provider logs are in their infrastructure, subject to their retention policies

### Infrastructure Policy (OPA + Envoy)

OPA+Envoy is the standard for service-to-service policy. The threat model is different:

- **OPA assumes honest clients**: Microservices are your own code, behaving as written. AI agents are autonomous and prompt-injectable
- **Binary enforcement**: Envoy interprets OPA decisions as allow/deny. GVM supports graduated enforcement (Delay, RequireApproval) for human-in-the-loop workflows
- **No agent-specific features**: No thinking trace capture, no credential isolation, no sandbox process isolation

OPA is a policy engine for microservices. GVM is a governance layer for AI agents. They solve different problems with surface-level similarity.

---

## GVM's Unique Position

GVM occupies the **action governance** layer — between the agent runtime and external APIs:

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────────┐
│ Prompt Guard │────>│  LLM + Agent │────>│  GVM Proxy  │────>│ External API │
│ (Lakera etc) │     │  (OpenClaw)  │     │ (audit+enforce)│  │ (Stripe etc) │
└─────────────┘     └──────────────┘     └─────────────┘     └──────────────┘
  Input/output         Generates           Intercepts           Receives
  content filter       API calls           every HTTP call      governed request
```

**Key differentiators:**
- **Cross-layer lie detection**: ABAC (what the agent claims) vs SRR (what the HTTP actually is). `max_strict()` catches mismatches automatically
- **Graduated enforcement**: Allow → Delay → RequireApproval → Deny. Not just binary allow/deny
- **Credential isolation**: Agent never holds API keys. Proxy injects post-enforcement
- **Durable audit**: WAL with Merkle chain. Every decision recorded before forwarding
- **Runtime isolation**: `gvm run --sandbox` provides namespace+seccomp+MITM. The agent physically cannot bypass the proxy
- **Provider-agnostic**: Works with any LLM, any framework, any language. It's an HTTP proxy

---

## When to Use What

| Scenario | Solution |
|----------|----------|
| Block prompt injection attempts | Lakera, Prompt Armor |
| Prevent harmful LLM outputs | Provider safety (Anthropic, OpenAI) |
| Control which APIs an agent can call | **GVM** |
| Audit every action an agent takes | **GVM** |
| Require human approval for high-risk actions | **GVM** |
| Service-to-service authorization | OPA + Envoy |

**Use all layers together.** Prompt guards + provider safety + GVM = defense in depth. No single layer is sufficient for autonomous AI agents.

---

[← Security Model](12-security-model.md) | [Overview →](00-overview.md)
