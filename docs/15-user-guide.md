# GVM User Guide

---

## 1. Running Agents

### Cooperative Mode

```bash
gvm run my_agent.py                    # Python script
gvm run -- node my_agent.js            # Node.js binary
gvm run -- openclaw gateway            # Any binary + args
```

에이전트의 HTTP 트래픽이 프록시를 통해 거버넌스됩니다. 코드 변경 불필요.

**출력:**
```
  Agent ID:     agent-001
  Security layers active:
    ✓ Layer 2: Enforcement Proxy
    ○ Layer 3: OS Containment (add --sandbox)

  --- Agent output below ---
  [agent runs here]

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  GVM Audit Trail — 5 events
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ✓ Allow    GET  api.github.com
    ⏱ Delay    POST slack.com
    ✗ Deny     POST api.bank.com

  3 allowed  1 delayed  1 blocked
```

> **참고:** Node.js는 `HTTPS_PROXY`를 무시합니다. HTTPS 관찰이 필요하면 `--sandbox`를 사용하세요.

### Sandbox Mode

```bash
sudo gvm run --sandbox my_agent.py
```

에이전트가 프록시를 우회할 수 없는 격리 환경에서 실행됩니다. Linux에서만 작동하며 sudo가 필요합니다.

```bash
--sandbox-timeout 300       # 5분 후 강제 종료 (기본: 3600)
--no-mitm                   # HTTPS 검사 비활성화
--memory 256m               # 메모리 제한
--cpus 0.5                  # CPU 제한
--fs-governance             # 파일 변경 거버넌스 (§6 참고)
```

### Watch Mode

```bash
gvm watch my_agent.py                     # 모든 요청 허용, 트래픽 관찰
gvm watch --with-rules my_agent.py        # 기존 룰 적용하면서 관찰
gvm watch --sandbox --output json \       # JSON 출력
  -- node agent.js
```

실시간 트래픽 표시:
```
  14:23:01  ✓ POST  api.anthropic.com    /v1/messages       200  [1,234 tokens]
  14:23:05  ⏱ GET   raw.githubusercontent /torvalds/linux..  301
  14:23:06  ✓ GET   api.github.com       /repos/torvalds..  200
```

종료 시 호스트 빈도, 결정 분포, 토큰 비용 추정, 이상 탐지(burst, loop, unknown host) 요약.

---

## 2. 정책 설정

### SRR 룰 — URL 패턴 매칭 (`config/srr_network.toml`)

SDK 없이 작동. 모든 언어의 에이전트에 적용됩니다.

```toml
# GitHub 읽기 허용
[[rules]]
pattern = "api.github.com"
path_regex = "^/repos/[^/]+/[^/]+/commits$"
method = "GET"
decision = { type = "Allow" }
reason = "List commits (read-only)"

# 송금 차단
[[rules]]
pattern = "api.bank.com"
path_regex = "/transfer/.*"
method = "POST"
decision = { type = "Deny", reason = "Wire transfers blocked" }

# 나머지: 지연 후 허용 (감사 추적 보장)
[[rules]]
pattern = "{any}"
method = "*"
decision = { type = "Delay", milliseconds = 300 }
```

**패턴:**
- `"api.github.com"` — 정확한 호스트
- `"api.github.com/{any}"` — 호스트 + 모든 경로
- `"{any}"` — 모든 요청 (Default-to-Caution)

**결정 유형:**
| 유형 | 동작 |
|------|------|
| `Allow` | 즉시 통과 |
| `Delay { milliseconds: N }` | N ms 지연 후 통과 |
| `Deny { reason: "..." }` | 403으로 차단 |
| `RequireApproval { urgency: "High" }` | 사람 승인 대기 |
| `Throttle { max_per_minute: N }` | 분당 N회 제한 |
| `AuditOnly { alert_level: "Medium" }` | 통과하되 경고 |

**핫 리로드:** 파일 수정 후 `POST /gvm/reload` 호출. 프록시 재시작 불필요.

**쿼리 스트링:** 자동으로 분리됩니다. `^/commits$`가 `/commits?per_page=5`에 매칭됩니다.

### ABAC 정책 (`config/policies/`)

SDK(`@ic` 데코레이터)와 함께 사용합니다.

```toml
# config/policies/global.toml

[[rules]]
id = "block-critical-delete"
priority = 1
layer = "Global"
description = "Block critical data deletion"

[rules.match]
operation = { starts_with = "gvm.data.delete" }

[rules.match.context]
sensitivity = { equals = "Critical" }

[rules.decision]
type = "Deny"
reason = "Critical data deletion is forbidden"
```

**정책 파일 구조:**
```
config/policies/
  global.toml             # 모든 에이전트에 적용
  tenant-acme.toml        # "acme" 테넌트에 적용
  agent-finance-001.toml  # 특정 에이전트에 적용
```

하위 레이어는 상위보다 **엄격해질 수만** 있고, 완화할 수 없습니다.

### Credential Injection (`config/secrets.toml`)

```toml
[credentials."api.stripe.com"]
type = "Bearer"
token = "sk_live_your_stripe_key"

[credentials."api.sendgrid.com"]
type = "ApiKey"
header = "x-api-key"
value = "SG.your_sendgrid_key"
```

| 에이전트 코드 | secrets.toml에 호스트 있음? | 결과 |
|-------------|------------------------|------|
| 키 없이 요청 | 있음 | 프록시가 키 주입 |
| 자체 키로 요청 | 있음 | 프록시 키로 **교체** |
| 자체 키로 요청 | 없음 | 에이전트 키 그대로 통과 |
| 키 없이 요청 | 없음 | 인증 없이 전송 |

> **범위:** HTTP 헤더만. LLM SDK(Anthropic, OpenAI)는 초기화 시 키가 필요하므로 `ANTHROPIC_API_KEY` 환경변수를 사용하세요. Credential injection은 LLM 응답 후 에이전트가 하는 **도구 API 호출**에 적용됩니다.

---

## 3. 트러블슈팅

### 에이전트가 차단됨 (403 Deny)

```bash
# 1. 무슨 일이 있었는지 확인
gvm events list --agent my-agent --since 5m

# 2. 같은 요청을 dry-run
gvm check --operation gvm.payment.charge --host api.bank.com --method POST

# 3. 정책 수정 (srr_network.toml 편집 → 핫 리로드)
```

### 에이전트가 지연됨 (300ms Delay)

URL이 SRR 룰에 매칭되지 않아 **Default-to-Caution**이 작동한 것입니다.

```bash
# 패턴 자동 발견
gvm watch --output json agent.py > session.jsonl
gvm suggest --from session.jsonl --output new-rules.toml

# 또는 직접 룰 추가
# config/srr_network.toml에:
# [[rules]]
# pattern = "catfact.ninja/{any}"
# method = "GET"
# decision = { type = "Allow" }
```

### 프록시가 안 뜸

```bash
# 로그 확인
cat data/proxy.log | tail -20

# 포트 충돌
lsof -i :8080

# sandbox는 sudo 필요
sudo gvm run --sandbox agent.py
```

---

## 4. CLI 명령어

### `gvm run`

```
gvm run [FLAGS] [--] <command...>

--sandbox              격리 환경 (sudo 필요)
--no-mitm              HTTPS 검사 비활성화
--fs-governance        파일 거버넌스 활성화
--shadow-mode <MODE>   disabled | observe | strict
--sandbox-timeout <N>  초 (기본: 3600)
--memory <SIZE>        256m, 1g (기본: 512m)
--cpus <N>             0.5, 1.0 (기본: 1.0)
-i, --interactive      실행 후 룰 제안
--default-policy <P>   allow | delay | deny
--agent-id <ID>        에이전트 식별자
--proxy <URL>          프록시 주소 (기본: http://127.0.0.1:8080)
```

### `gvm watch`

```
gvm watch [FLAGS] [--] <command...>

--with-rules           기존 룰 적용하면서 관찰
--sandbox              sandbox에서 관찰
--output <FORMAT>      text (기본) | json
```

### `gvm check`

정책 dry-run — 실제 요청 없이 결정 확인.

```bash
gvm check --operation gvm.payment.charge --host api.bank.com --method POST
gvm check --operation test --host api.github.com --method GET --path /repos
```

출력: 결정, 매칭된 룰, 결정 경로, 엔진 지연시간.

### `gvm events`

```bash
gvm events list [--agent <ID>] [--since <DURATION>] [--format json]
gvm events trace --trace-id <UUID>
```

### `gvm audit`

```bash
gvm audit verify [--wal data/wal.log]
gvm audit export [--since 1h] [--format jsonl]
```

출력 예시:
```
OK: WAL integrity verified. Events: 635, Batches: 42, Chain: intact
```
```
TAMPER DETECTED: 2 event(s) have invalid hashes. Batch 7: merkle root mismatch
```

### `gvm stats`

```bash
gvm stats tokens [--agent <ID>] [--since 1h]
gvm stats rollback-savings [--since 24h]
```

### `gvm suggest`

```bash
gvm suggest --from session.jsonl [--output rules.toml] [--decision allow]
```

`gvm watch --output json`의 결과에서 Default-to-Caution에 걸린 URL의 TOML 룰을 생성합니다.

### `gvm cleanup`

```bash
gvm cleanup              # 이전 크래시의 잔여 리소스 정리
gvm cleanup --dry-run    # 정리 대상만 표시
```

### `gvm init`

```bash
gvm init --industry saas          # SaaS 템플릿
gvm init --industry healthcare    # HIPAA 기본값
```

---

## 5. Shadow Mode

```bash
gvm run --shadow-mode strict -- node agent.js
```

| 모드 | 미선언 요청 | 용도 |
|------|-----------|------|
| `disabled` | 일반 처리 | 기본값 |
| `observe` | 허용 + 감사 경고 | 테스트 |
| `strict` | 거부 (403) | 프로덕션 |

MCP 연동: `gvm_declare_intent` 도구로 intent 등록 후 API 호출. [MCP 섹션 →](12-quickstart.md#7-mcp-integration--claude-desktop--cursor)

---

## 6. 파일 거버넌스 (Trust-on-Pattern)

```bash
sudo gvm run --sandbox --fs-governance my_agent.py
```

에이전트의 파일 변경을 세션 종료 시 분류하고 검토합니다.

| 변경 | 패턴 | 처리 |
|------|------|------|
| 새 파일 | `*.csv, *.pdf, *.txt` | 자동 복사 |
| 새 파일 | `*.sh, *.py, *.json` | 수동 검토 |
| 새 파일 | `*.log, __pycache__/*` | 폐기 |
| 수정된 파일 | (모든 패턴) | 수동 검토 |
| 삭제된 파일 | (모든 패턴) | 수동 검토 |

**TTY:**
```
  ── File Changes ──
    Created:  output.csv (12KB)  auto-merged → workspace/output.csv
    Created:  analysis.py (2KB)  needs review (*.py)

  [1/1] analysis.py (Created, 2KB)
  +#!/usr/bin/env python3
  +import pandas as pd

  (a)ccept  (r)eject  (s)kip all → a
  ✓ analysis.py → workspace/analysis.py
```

**CI/CD:** 파일이 `data/sandbox-staging/`에 보존됩니다. `gvm fs approve`로 나중에 처리.

---

## 7. CI/CD 통합

```yaml
# GitHub Actions
- name: Validate governance policies
  run: |
    gvm-proxy &
    sleep 2
    gvm check --operation gvm.payment.charge --host api.bank.com --method POST \
      | grep -q "Deny" || exit 1
    gvm check --operation gvm.storage.read --host api.github.com --method GET \
      | grep -q "Allow" || exit 1
```

### 패턴 발견 + 룰 생성

```bash
gvm watch --output json agent.py > session.jsonl
gvm suggest --from session.jsonl --decision allow > new-rules.toml
```

---

## 8. 프로덕션 체크리스트

- [ ] `proxy.toml`에서 `[dev] host_overrides` 제거
- [ ] `GVM_SECRETS_KEY` 설정 (vault 암호화)
- [ ] `GVM_VAULT_KEY` 설정 (state 암호화)
- [ ] NATS WAL 복제 설정 (`proxy.toml [nats]`)
- [ ] credential 정책을 `Deny`로 변경 (Passthrough 아님)
- [ ] `--shadow-mode strict` 활성화
- [ ] `chmod 600 config/secrets.toml`
- [ ] SRR 룰 검토: catch-all Allow 없는지, Default-to-Caution이 Delay인지
- [ ] 모니터링: `gvm stats tokens` + `gvm audit verify` 크론 설정
- [ ] 배포 전 `gvm check`로 정책 검증

---

> **내부 동작 원리**가 궁금하다면: [Architecture Overview](00-overview.md) | [SRR 설계](03-srr.md) | [ABAC 정책 엔진](02-policy.md) | [Merkle WAL](04-ledger.md) | [Security Model](11-security-model.md) | [Governance Coverage](14-governance-coverage.md)
