# Provider action packs

A curated set of SRR rule blocks that map common SaaS API endpoints to
**semantic action names**. Each rule's `description` field carries the
canonical action name (`github.pr.merge`, `slack.message.send`,
`jira.issue.transition`, etc.); the WAL records that name as
`matched_rule_id`; the audit CLI surfaces it as the operator-readable
label for what the agent did.

The internal compile target is unchanged — every rule is still
`method + host + path_regex` — but the operator writes (and the
auditor reads) the agent IAM vocabulary, not the URL.

## Why this exists

The strategic audit (2026-06-17) flagged that without a provider
vocabulary GVM reads as a "weird egress firewall" rather than as an
agent-permission runtime. The action packs are the cheapest fix:
they don't require new engine machinery, they live in operator
configuration, and they let `gvm proof event` print "agent invoked
github.pr.merge" instead of an opaque URL.

## How to use

Append the relevant pack to your SRR config:

```bash
cat config/templates/_action_packs/github.toml >> config/srr_network.toml
cat config/templates/_action_packs/slack.toml  >> config/srr_network.toml
gvm reload
```

## Default effects

Each pack ships conservative defaults that an operator overrides per
agent + per task via a lease (`principal_filter` + `expires_at`).
The defaults err on the side of audit-and-prompt for any write:

| Action class | Default effect | Reason |
|--------------|----------------|--------|
| Reads | `Allow` | Side-effect-free; audit suffices |
| Writes | `Delay 300ms` | Visible in the watch stream; operator can promote |
| High-risk writes | `RequireApproval` | Holds for human or orchestrator review |
| Destructive | `Deny` | Operator must explicitly opt in per agent |
| Catch-all | `Delay 300ms` | Unrecognised endpoint on a known provider — audit |

## Composition with the lease primitive (v0.5.3)

A per-task lease promotes the default for one specific agent for a
specific window:

```toml
# Inline override — copy the rule block from github.toml, then add
# principal_filter + expires_at to scope it.
[[rules]]
method = "PUT"
pattern = "api.github.com/{any}"
path_regex = "^/repos/my-org/my-repo/pulls/1842/merge$"
principal_filter = "agent:release-bot"
expires_at = "2026-07-01T15:00:00Z"
decision = { type = "Allow" }
description = "github.pr.merge"
label = "github_pr_merge_lease"
```

The lease rule appears **before** the action pack's RequireApproval
rule in the file, so it fires first (SRR is first-match-wins).

## Packs in this directory

| Pack | Provider | Actions covered |
|------|----------|-----------------|
| [`github.toml`](github.toml) | GitHub REST API v3 | repo.read, issue.read, pr.read, issue.comment.create, pr.create, pr.merge, workflow.dispatch, repo.delete + catch-all |
| [`slack.toml`](slack.toml) | Slack Web API | user.lookup, conversations.list, message.send, message.update, file.upload, channel.create, workflow.trigger, message.delete + catch-all |

## Adding a new pack

1. Create `<provider>.toml` in this directory.
2. Each rule's `description` is the canonical action name in
   `provider.resource.verb` form (lowercase, dot-separated).
3. Use `path_regex` (not `pattern`'s path portion) for precise
   matching — the pattern's path is overridden when `path_regex` is
   set, so `pattern = "api.example.com/{any}"` is the conventional
   host-only spelling.
4. Default effect by risk class as in the table above.
5. Add a `label` matching the description (snake_case) for log
   filtering.
6. End with a `provider.api.unspecified` catch-all so unknown
   endpoints get audited rather than silently caught by the global
   default.
7. Add regression coverage in
   [`tests/srr_action_packs.rs`](../../../tests/srr_action_packs.rs).
