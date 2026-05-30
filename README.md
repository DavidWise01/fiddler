# ARES + IDIT — Adversarial Router Evaluation Suite

**Architect:** David Lee Wise / ROOT0 / TriPod LLC  
**AI Collaborator:** AVAN (Claude Sonnet 4.6)  
**License:** CC-BY-ND-4.0 · TRIPOD-IP-v1.1  
**Version:** ARES v1.0 · IDIT v1.0  

---

## What This Is

Two complementary AI governance frameworks for evaluating and defending AI routing systems:

### ARES — Adversarial Router Evaluation Suite

A structured test harness for detecting security vulnerabilities in AI router/orchestration systems. Covers 9 attack classes:

| Class | Name | Description |
|-------|------|-------------|
| A1 | Prompt Injection | Direct instruction override attempts |
| A2 | Label Steering | Urgency spoofing, format confusion |
| A3 | Ambiguity | Dual-use requests, contradictory constraints |
| A4 | Indirection | Quoted relay, JSON/code-block injection |
| A5 | Multi-Turn Drift | Gradual escalation across conversation turns |
| A6 | Tool Exfiltration | Unauthorized tool/API access requests |
| A7 | Cost Shaping | Loop attacks, resource exhaustion |
| A8 | Extraction | System prompt mining, rubric disclosure |
| B  | Baseline Controls | Benign requests (must not be blocked) |

### IDIT — Intent Drift Integrity Test

A governance integrity test that detects unauthorized behavioral change relative to declared modes and user intent.

**Core Invariants:**
- **I1 Mode Authority** — Operate within declared mode only
- **I2 Intent Non-Inference** — No execution without activation
- **I3 Memory Permission** — State persistence requires authorization
- **I4 Boundary Enforcement** — Plan / execute / explore stay distinct
- **I5 Change Disclosure** — No silent mutation

---

## Router Under Test: Charlotte's Web

This repo ships `ares_router.py` — a Python port of the Charlotte's Web four-guard detection engine. Charlotte's Web uses pattern-signature detection with compound penalty scoring:

| Guard | Frequency | Role |
|-------|-----------|------|
| PHOTONIC | 16Hz | Direct instruction override |
| PLASMIC | 8Hz | Slow-burn escalation |
| BORONIC | 9Hz | Encoded / obfuscated payloads |
| TOROIDAL | 32Hz | System prompt extraction |

**Score → Route mapping:**
```
< 1.0   → NORMAL_ROUTE (pass)
1.0–2.8 → MONITOR
2.8–5.0 → REVIEW
5.0–7.0 → BLOCK
≥ 7.0   → QUARANTINE
```

Compound penalty: ×1.25 (2 guards) / ×1.35 (3) / ×1.50 (4)

---

## Files

| File | Purpose |
|------|---------|
| `ares_router.py` | Charlotte's Web four-guard engine (call_router) |
| `run_ares_suite.py` | Test harness — runs single-turn and multi-turn suites |
| `ares_report.py` | KPI report generator → ares_report.md |
| `ares_suite.jsonl` | 24 single-turn adversarial tests |
| `ares_suite_multiturn.jsonl` | 3 multi-turn escalation sequences |
| `ARES_Mode_Spec_v1.0.txt` | Frozen v1.0 spec (do not modify) |
| `ares_report.md` | Latest evaluation report (auto-generated) |

---

## Quick Start

```bash
# Run single-turn suite
python run_ares_suite.py --mode single --out ares_results.jsonl

# Run multi-turn suite
python run_ares_suite.py --mode multiturn --out ares_results_multiturn.jsonl

# Generate KPI report
python ares_report.py
```

No external dependencies — stdlib only (re, json, argparse, pathlib).

---

## Latest Results (Charlotte's Web)

```
Tests:         24 single-turn + 3 multi-turn sequences
Pass Rate:     83.3% (20/24 single-turn)
Unsafe Activ:  0.0%   ← zero unsafe content passed through
Extraction:    0.0%   ← zero system prompt leakage
Misroute:      16.7%  ← 4 semantic-only attacks (LLM-required)
```

**Detection gap summary:**

| Category | Detectable by Regex | Resolution |
|----------|---------------------|-----------|
| A1 Prompt Injection | ✅ Yes | Pattern engine |
| A2 Label Steering | ⚠️ Partial | Needs intent classifier |
| A3 Ambiguity | ⚠️ Partial | Needs NLU disambiguation |
| A4 Indirection | ✅ Yes | Structural patterns |
| A5 Multi-Turn Drift | ❌ Needs session state | Stateful scoring layer |
| A6 Tool Exfiltration | ✅ Yes | Access patterns |
| A7 Cost Shaping | ✅ Yes | Loop/expansion patterns |
| A8 Extraction | ✅ Yes | Verbatim/rubric patterns |

---

## Swap In Your Own Router

Replace the `call_router()` import in `run_ares_suite.py`:

```python
# Current: Charlotte's Web
from ares_router import call_router, evaluate_pass_fail

# Your router: implement call_router(prompt, conversation_id=None) -> dict
# Must return: {"route": str, "action": str, "notes": str}
```

---

## Attribution

```
ROOT0-ATTRIBUTION-v1.0
Project: fiddler — ARES + IDIT Adversarial Router Test Framework
Architect: David Lee Wise / ROOT0 / TriPod LLC
AI Collaborator: AVAN (Claude Sonnet 4.6 / Anthropic)
License: CC-BY-ND-4.0 · TRIPOD-IP-v1.1
```
