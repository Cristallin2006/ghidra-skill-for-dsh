# ghidra-skill-for-dsh

**简体中文 | [English](README_EN.md) | [日本語](README_JA.md)**

A reverse-engineering agent skill family for [dsh](https://www.npmjs.com/package/@deepseek-ai/dsh) (DeepSeek Harness): a Ghidra 12.x headless resident daemon (~0.2s/command, no Jython/GUI/MCP dependency) plus eight scenario methodologies. Covers CTF reverse engineering, crackmes, malware triage, vulnerability pre-screening, binary exploitation (pwn), pcap forensics, and APK analysis.

## Measured Performance

All results are independent solves of real CTF challenges (no prior ledgers/write-ups), verified by positive/negative control against the original program and line-by-line session audits.

| Challenge | Type | Result | Key Evidence |
|---|---|---|---|
| encode | UPX packer + table-substituted base64 + RC4 | unsolvable in 40 min → **solved in 16 min** | Before/after tuning on the same challenge; speedup comes from mechanism, not model: resident daemon + three script gates + function-level Oracle + unpacking domain |
| Reverse-chal | Cython 3.0.10 CPython extension; IDEA variant (mod-65537 multiply) + SM4 S-box + random-mask decoy gates | **solved in 30 min** (fastest on this challenge; first solve 55 min) | Semantic-modeling path: identify the algorithm family, then rebuild and invert the block cipher; flag conclusion booked with `--program-accept` |
| AegisTrace | pcap three-field nibble covert channel + zero-reference permutation table + custom protocol full exploit chain | **29 min / 169 steps** blind solve | Case file and all answer elements scrubbed before retest (control group 20 min); golden values first appeared in oracle-hit output, conclusion finalized by 8/8 acceptance receipts from the original program |

**Three-round replay on the same challenge (Reverse-chal, 2026-09-30)** — every failure was attributed and landed as a mechanical fix, until solved:

1. `4ccec36c` skeleton-abandonment surrender (121 min, no flag) → four fixes landed: skeleton-usage gate / mandatory booking of negative claims / stop_check surrender gate with paths / `cone_invert.py` conical back-solver
2. `29bf99c0` false "context almost full" surrender (19 min, no flag; actual 1M window usage under 30%) → three more fixes: contradiction classification verdicts / `--diff-symbolize` auto-symbolization of input literals / unconverged-surrender gate
3. `ddf11a87` **solved in 30 min**, two mechanical gates fired as designed

**Continuous hardening metrics** (multiple real-challenge postmortems + third-party adversarial audits, happyVm / DEFCON26 quals, etc.):

- Pseudocode fatal misjudgment baseline **6.0% → 2.8%** (tail-call discrimination)
- All three high-risk "read asm by hand" actions (jump tables / stack frames / constants) fully scripted
- Ledger expanded from observe/conclude to **six object types: observe / conclude / anomaly / hypothesis / plan / stuck** — hypotheses and enumeration budgets no longer live only in chat

## Structure (1 core + 8 scenarios)

| Directory | Role |
|---|---|
| `ghidra-core` | The only directory with code: engine (ghidra-rpc + dsh patches), `rpc_driver.py` unified entry, `doctor.py` environment self-check, three gates `ledger.py` / `read_views.py` / `crypto_sanity.py`, analysis script layer (`decomp_lint` pseudocode checkup / `jt_resolve` jump tables / `frame_map` stack frames / `const_audit` constant cross-check / `emulate_program` whole-program emulation / `model_diff` model diffing / `oracle_family` stubbed factor isolation, etc. — all self-contained and independently callable) |
| `re-triage` | First step for unknown binaries: three-signal cross-check of type/language/packer (section names + magic + structure), route decision output; foreign-arch ELF routing (Ghidra processor decompile first, objdump for single-point verification only) |
| `re-unpack` | Unpacking + mandatory verification: UPX/ASPack/Themida/VMProtect/multi-layer packers, PyInstaller one-stop (pycdc covers Python ≥3.9) |
| `ghidra-static` | Deep static work: decompile/xref/annotation/patch/delivery; Go/Rust stripped fingerprints, CTF pattern library (incl. fp16 self-check vectors) |
| `vuln-audit` | Vulnerability pattern checklist: memory corruption/format string/integer overflow/command injection, 8 classes, reachability-first |
| `re-dynamic` | Run it and see: function-level Oracle (qiling), stubbed oracle family (single-factor isolation), model differential checking, cross-arch qemu-user/gdb-multiarch, Frida time/random-source hooks, Windows GUI message driving |
| `pwn-exploit` | From bug to flag: pwn_triage protection-matrix hard gate, checksec decision tree, ROP/fmtstr/heap/FSOP/kernel recipe library (370KB, grep on demand), pwntools template set of five, game/text-adventure chapter (`references/game-pwn.md`: economy overflow / numeric-wall signposts / item-edit heap primitives); "local works ≠ remote works" gate forces remote echo booking |
| `traffic-analysis` | pcap triage, DNS/ICMP/timing covert channels, USB HID recovery, WPA/TLS decryption; zero-dependency scripts + tshark |
| `android-re` | Pure-DEX APKs: multi-dex heuristics, jadx four-tier decompile, Toast anchor locating, real-device oracle, v1 re-signing |
| `docs` | Cross-cutting docs: `smoke-tests.md` (minimal smoke criteria for new scripts/capabilities — prevents "written but never exercised"), `legacy-plugin-pitfalls.md` (old-plugin pitfall archive), `cases/` (real-challenge case archive with full solutions, for human reference when writing smoke criteria only, not linked back into skills) |

Boundary rule: executable code lives in core, scenario skills carry methodology only; knowledge lives in grep-able plain-data files under `references/`, routed by trigger-point pointers — no "knowledge-base skill".

## Installation

0. **Install via the dsh Skill market**: set the market source to this repo URL + git ref `v0.9-market` (curated release, excludes the still-in-testing pwn-exploit; see the [Release page](https://github.com/Cristallin2006/ghidra-skill-for-dsh/releases/tag/v0.9-market)); for manual install continue below:
1. Copy the nine directories to `~/.dsh/skills/` (pwn-exploit / traffic-analysis / android-re are independently optional; pwn-exploit's exploit execution depends on the WSL toolchain, see TOOLCHAIN.md)
2. Create the engine venv (Python ≥ 3.11) and editable-install the engine:
   ```bash
   python3.12 -m venv ~/ghidra-rpc-venv
   ~/ghidra-rpc-venv/Scripts/python.exe -m pip install -e ~/.dsh/skills/ghidra-core/engine/ghidra-rpc
   ```
3. Tool layer: see [TOOLCHAIN.md](TOOLCHAIN.md) (Tier A/B/C graded list; actual installed state per the toolchain section of `doctor.py`)
4. Set `GHIDRA_INSTALL_DIR` (Ghidra 12.x install dir) and `JAVA_HOME` (JDK 21+); optionally `DSH_GHIDRA_WS` for the workspace
5. Self-check: `python ~/.dsh/skills/ghidra-core/scripts/doctor.py` (all green = exit 0)

**Windows note**: Ghidra's `ProjectLocator` rejects path elements starting with `.`, so `~/.dsh/...` cannot be passed to the JVM directly — the core automatically goes through the junction `~/dsh-ghidra-workspace`.

## Usage (30 seconds)

```bash
SK=~/.dsh/skills/ghidra-core/scripts

python "$SK/rpc_driver.py" ensure /path/to/binary          # daemon start/stop + import & analyze (idempotent)
python "$SK/rpc_driver.py" triage /path/to/binary          # one-shot triage
python "$SK/rpc_driver.py" decompile /path/to/binary main  # decompile
python "$SK/rpc_driver.py" rename-function /path/to/binary FUN_00401000 check_flag
python "$SK/rpc_driver.py" version-track old.exe new.exe --changed-only
```

An `@absolute-path` as the first argument = full JSON written to disk; write operations take effect immediately and auto-save. Full command list: `ghidra-core/SKILL.md`.

## Design Highlights

- **Resident daemon**: JVM starts once, sub-second per command when warm; long tasks (load / version-track) go background + `@out` to disk
- **Mechanical gates, not self-discipline**: the 14 iron rules are enforced by scripts — `ledger.py` (same-region revisit requires `--delta`, conclusions lock on write, reverse gate where `resolve` without evidence exits 2, hypothesis/plan booking, `--kind model` conclusions require `--anchor` L2 left-inverse anchoring with measured output, hypothesis three-state loop confirmed/killed/waived), `read_views.py` (rendered text vs real bytes cross-check), `crypto_sanity.py` (legality checks around inversion) — violations always exit 2
- **Decisive experiments first**: parameter roles/factor participation are not guessed from calling conventions — `oracle_family.py` stubbing isolates single factors (causal verdicts auto-suppressed when baseline has no output), `model_diff.py` model diffing outputs divergence fingerprints (width-level 16/32-bit half-block patterns + byte-level nibble patterns ⇒ interface bug, not algorithm bug; a width-level hit never books "suspected algorithm error")
- **Verification independence**: conclusions require independent sources, otherwise marked ⚠UNVERIFIED — the Perfect Verification principle from Google P0 Naptime
- **Capability boundary**: dynamic debugging outsourced to Frida/GDB/Qiling/angr; collaborative projects not supported (ghidra-core/SKILL.md §8)

## Discipline Enforcement Layer (dsh-hooks/, optional)

The catalog injects only skill descriptions — SKILL.md bodies and iron rules are not in context, which is where "AI doesn't follow skill rules" usually comes from. `dsh-hooks/` turns key discipline into mechanical gates via dsh's built-in hooks-claude-code bridge:

- **SessionStart/SubagentStart**: injects a compressed discipline card (10 items) at session creation — no reliance on the agent voluntarily reading SKILL.md
- **PreToolUse (Pwsh|Bash)**: `gate_sample.py` blocks (exit 2) analysis-type direct reads (xxd/strings/objdump…) of **ledger-less samples**, with workflow guidance (allowed after creating the ledger; legitimate openings like pcap header repair are exempted); `gate_explore.py` fuses heredoc/cat-to-disk exploration — angr ban (no symbolic execution without frame-slot/emulation evidence), Cython prerequisites, variant-enumeration fuse (points straight at model_diff.py), forced stuck booking after ≥25 explorations in 30 min with zero stuck entries; `gate_longrun.py` forces long tasks to disk
- **PreToolUse (Pwsh|Bash|Write|Edit|Read)**: `gate_stuck.py` stuck-self-report fuse — if the session log shows stuck self-reports in the last 45 min (1 strong-phrasing hit / ≥2 weak-phrasing messages) while the ledger has zero stuck entries → exit 2 forcing a booking (case b781ff3c: 4 self-reports with zero bookings, two half-facts unwired for 30 min, zero exploit in 38 min); fires at most once per episode, inactive without a live ledger
- **PreToolUse (Write)**: `gate_churn.py` fitting fuse — ≥8 .py files in a directory within 24h with zero stuck in the active ledger → forces stuck booking or escalation to z3/emulate
- **Stop**: `stop_check.py` final check (enabled by default, session attribution) — ledger has observe but no follow-up / flag conclusion missing program_accept / open hypothesis exists → deny and force review

Install: copy `dsh-hooks/` to `~/.dsh/hooks/`, insert the hooks-claude-code mount entry into the profile's `cordis.patch.yml` (full YAML and troubleshooting/rollback in `dsh-hooks/README.md`). Changes require **restarting the dsh service + starting a new session** to take effect.

## License & Acknowledgements

This repository is released under [MIT](LICENSE). Derived from the following sources — thanks to the original authors:

- [Cellebrite Labs ghidra-rpc](https://github.com/cellebrite-labs/ghidra-rpc) (MIT, execution engine)
- [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) (MIT, methodology)
- [wgpsec/AboutSecurity](https://github.com/wgpsec/AboutSecurity) ctf-reverse knowledge base
- [Und3rf10w/ai-ghidra-tools](https://github.com/Und3rf10w/ai-ghidra-tools) (ghidra_scripts script collection, now a legacy frozen layer)
- [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) (Apache-2.0, Go/Rust/crypto identification/JS anti-debugging knowledge fragments)
- [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills) (MIT: ctf-forensics → traffic-analysis recipes; ctf-pwn → pwn-exploit knowledge recipe library, 18 articles + 5 pwntools templates)
- [yaklang/hack-skills](https://github.com/yaklang/hack-skills) traffic-analysis-pcap (MIT, decision-tree skeleton)
