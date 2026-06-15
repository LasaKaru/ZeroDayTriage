# ZeroDayTriage

**An orchestration + AI-triage layer for Project ZeroDay 2026 — the EVIL CORP banking
Active Directory live-hacking event.**

> Built on a deliberate strategic bet: the winners of AD CTFs do not rebuild scanners — they
> orchestrate proven tools fast and reason about the next move correctly. ZeroDayTriage is the
> *brain*, not another exploit. It ingests the output of battle-tested tools (BloodHound /
> SharpHound, NetExec, Certipy, Slither, …), normalizes everything into one shape, correlates
> findings into ranked attack paths, and tells the operator the single highest-value next
> action — while filtering the noise.

```
┌─────────────────────────────────────────────────────────────┐
│  ztriage (.NET 8 CLI)                                         │
│  ingest → normalize → persist → reason → prioritized report  │
└───────────────┬─────────────────────────────┬───────────────┘
                │                             │
      ┌─────────▼─────────┐         ┌─────────▼──────────────┐
      │ Tool Normalizers  │         │ Reasoning Engine        │
      │  BloodHound CE     │         │  attack-path rules      │
      │  NetExec (nxc)     │  ──►    │  Kerberoast / AS-REP    │
      │  Certipy (ESC1-8)  │ Finding │  ADCS / ACL / PtH /     │
      │  Slither (Solidity)│  JSON   │  coerce-relay / chain   │
      └────────────────────┘         │  priority scorer        │
                │                    └─────────────────────────┘
      ┌─────────▼─────────┐
      │ SQLite findings   │
      │ store (idempotent)│
      └───────────────────┘
```

## Why this design

| The instinct | Why it loses | What ZeroDayTriage does |
| ------------ | ------------ | ----------------------- |
| Build one C# scanner that "finds vulns with AI" | Reinventing BloodHound/Rubeus/Impacket in event time is a losing trade; AI does not autonomously out-exploit a skilled operator | Orchestrate the proven tools; use reasoning for **triage and decision speed** |
| Dump raw tool output and read it manually | Drowns the operator in noise under time pressure | Normalize to one schema, **rank attack paths**, surface one next action, suppress noise |
| Treat each finding in isolation | Misses the chains that actually reach Domain Admin | **Fuses** correlated findings (e.g. Kerberoastable *and* GenericWrite on the same principal) |

The four operator loops the tool accelerates: **Enumerate → Identify path → Exploit → Loot & pivot.**

## Full kill-chain coverage (the five EVIL CORP phases)

Project ZeroDay is not just an AD privesc box — it models the whole EVIL CORP banking
intrusion. ZeroDayTriage covers all five progressive phases, ingesting the right evidence and
reasoning a response/exploitation path for each:

| # | Phase | Evidence ingested | Rule output |
| - | ----- | ----------------- | ----------- |
| 1 | **Initial Intrusion & Recon** | Suricata IDS alerts (SocGholish / fake-update / drive-by) | scope patient zero, recover the dropped payload, pivot to its C2 |
| 2 | **Command & Control Evasion** | RITA beacon analysis + Suricata C2 signatures | trace the encrypted channel, extract C2 infra as IOCs, scope every beaconing host |
| 3 | **Privilege Escalation & Lateral Movement** | BloodHound graph (membership/AdminTo/sessions/RDP/PSRemote), NetExec, Certipy | Kerberoast, AS-REP, ADCS ESC1–8, ACL chains, PtH, coerce-relay, **DCSync → golden ticket**, unconstrained delegation, **graph shortest-path to Domain Admin**, lateral movement |
| 4 | **Malware Triage** | malware config-extractor JSON (Dridex/ransomware) | recover crypto keys + C2, fuse into one decrypt-and-scope action; ransomware auto-detected |
| 5 | **Data Exfiltration** | Suricata exfil alerts (bulk upload / DNS tunneling) | identify the targeted DB records, quantify and contain the channel |

Every triage report prints a coverage line so you can see at a glance which phases have an
actionable path:

```
kill-chain coverage: [x] 1.Initial  [x] 2.C2  [x] 3.PrivEsc  [x] 4.Malware  [x] 5.Exfil
```

## Solution layout

| Project | Responsibility |
| ------- | -------------- |
| `ZeroDayTriage.Core` | Domain model (`Finding`, `AttackPath`, `TriageReport`), abstractions, the indexed `FindingCorpus` |
| `ZeroDayTriage.Tools` | `ProcessRunner` (subprocess execution) and normalizers for each proven tool |
| `ZeroDayTriage.Reasoning` | Attack-path rules, the `PriorityScorer`, and the `ReasoningEngine` |
| `ZeroDayTriage.Storage` | Idempotent SQLite finding store |
| `ZeroDayTriage.Cli` | `ztriage` console app: `demo`, `ingest`, `triage`, `list` |

## Build & test

```bash
dotnet build
dotnet test            # 94 tests across 5 suites
```

## Running in Visual Studio

This solution has **five class libraries and one executable** (`ZeroDayTriage.Cli`). If you press
F5 while a library is the startup project, Visual Studio shows:

> *A project with an Output Type of Class Library cannot be started directly.*

That just means VS is pointed at a library. Fix it once:

1. In **Solution Explorer**, right-click **`ZeroDayTriage.Cli`** → **Set as Startup Project**
   (it will show in **bold**).
2. Pick a launch profile from the **Run** dropdown in the toolbar — `ztriage (demo)` is a good
   first run. The bundled profiles are `demo`, `help`, `ingest samples`, and `triage samples`.
3. Press **F5** (debug) or **Ctrl+F5** (run without debugging).

The libraries (`Core`, `Tools`, `Reasoning`, `Storage`) are meant to be *referenced*, not run —
only the CLI is an executable. From the command line none of this matters; just target the CLI
project as shown below.

## Usage

```bash
# 1. See the whole engine on the built-in EVIL CORP scenario
dotnet run --project src/ZeroDayTriage.Cli -- demo

# 2. Ingest a directory of real tool dumps into an engagement database
dotnet run --project src/ZeroDayTriage.Cli -- ingest --input ./loot/ --db engagement.db

# 3. Reason over what you've collected and emit a prioritized report
dotnet run --project src/ZeroDayTriage.Cli -- triage --db engagement.db --format markdown --output report.md

# 4. List stored findings
dotnet run --project src/ZeroDayTriage.Cli -- list --db engagement.db
```

The `samples/` directory contains representative tool output you can ingest immediately:

```bash
dotnet run --project src/ZeroDayTriage.Cli -- ingest --input samples/ --db /tmp/eng.db
dotnet run --project src/ZeroDayTriage.Cli -- triage --db /tmp/eng.db
```

### Supported tool inputs

| Tool | Format | Findings extracted |
| ---- | ------ | ------------------ |
| SharpHound / BloodHound CE | collection JSON | Kerberoastable SPNs, AS-REP roastable, unconstrained delegation, dangerous ACEs (GenericAll/Write, WriteDacl/Owner, DCSync), **and graph edges**: group membership, AdminTo, HasSession, CanRDP/PSRemote/DCOM, high-value flags |
| NetExec (nxc) / CrackMapExec | console output | valid credentials, pass-the-hash + local admin, SMB signing posture |
| Certipy | `find` JSON | AD CS template vulnerabilities ESC1–ESC8 |
| Suricata | EVE NDJSON | IDS alerts classified into Initial Access / C2 / Exfiltration |
| RITA | beacon-analysis JSON | encrypted C2 beaconing, scored by regularity |
| Malware config extractor | JSON | family, extracted crypto keys, embedded C2, host IOCs; ransomware detection |
| Slither | `--json` | Solidity defects mapped onto the severity scale |

New tools are added by implementing `INormalizer`; new attack knowledge by implementing
`IAttackPathRule`. The engine discovers both through their registries.

### BloodHound enumeration & shortest path to Domain Admin

The BloodHound normalizer emits graph **edges** (group membership, AdminTo, HasSession,
CanRDP / CanPSRemote / ExecuteDCOM) alongside account primitives. `ShortestPathToDomainAdminRule`
loads them into an in-memory `AttackGraph` and runs **Dijkstra** from every owned foothold
(cracked/valid credentials) to the nearest high-value target (Domain Admins, or any
DCSync-capable principal), encoding each edge's real-world difficulty as its traversal cost.
The result is the classic BloodHound answer — *the shortest route to Domain Admin* — rendered as
a concrete, tool-by-tool plan:

```
Shortest path to domain admins: jdoe -> domain admins (3 hop(s))
  jdoe -> [adminto] ws01 -> [hassession] svc_adm -> [memberof] domain admins
    1. Use jdoe's local-admin rights on ws01 to execute and dump credentials.
    2. Dump the logged-on session of svc_adm from ws01's memory.
    3. Inherit Domain Admins through svc_adm's membership.
```

## How the reasoning works

1. **Normalize** — every tool's output collapses to `Finding` records with a deterministic
   content fingerprint (so re-ingesting is idempotent).
2. **Correlate** — rules query a pre-indexed `FindingCorpus` and emit candidate `AttackPath`s.
   Rules fuse signals: a Kerberoastable account that *also* holds `GenericWrite` becomes one
   Critical chain, not two unrelated findings.
3. **Score** — `PriorityScorer` rewards impact and confidence, adds a crown-jewel bonus for
   paths reaching DCSync / Domain Admin, and penalizes long fragile chains — encoding the
   instinct to take the shortest reliable route to DA.
4. **Triage** — the engine ranks all paths, recommends the top action, and lists what it
   suppressed as noise so nothing is silently dropped.

## Testing

The suite is intentionally thorough — unit tests for every normalizer (including
malformed-input resilience), every attack-path rule, the scorer's monotonicity properties,
engine ranking and noise-filtering, fault isolation (a throwing rule cannot sink a pass),
SQLite idempotency / severity-escalation semantics, and **real subprocess** tests for the
process runner (stdout/stderr capture, non-zero exit, timeout, external cancellation).

## Scope & authorized use

This tool reads the output of other tools and reasons about it. It performs **no exploitation
itself** — every recommendation is a suggested command for an operator to run. Use it only
within the bounds of an authorized engagement, CTF, or lab (such as Project ZeroDay 2026).
Operational databases and loot are git-ignored by default.

---

Built for VULNHAT Security Team · Project ZeroDay 2026 · the first AD live-hacking event in Sri Lanka.
