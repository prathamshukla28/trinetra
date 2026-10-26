# REFORGE

**Tear it down, then forge it back.**

Point REFORGE at any app or binary. It takes the target apart, writes down
everything it learns, flags the security weaknesses, and (optionally) rebuilds a
clean, tested version you own.

One run → two outputs:

- **A security report** — how it works + where it's weak.
- **A clean reimplementation** — tested code you own.

> ⚠️ **Authorized use only.** REFORGE is for software you own, open-source
> projects, authorized pentest engagements, and practice/CTF targets. Do not use
> it on software you are not permitted to analyze.

---

## The idea in one line

> **Reverse-engineer → understand → audit → rebuild**, with every step driven by
> disciplined, mistake-proofed agent skills.

Nobody has wired a *reverse-engineering* engine into a *disciplined builder*. That
is the gap REFORGE fills.

## How it's built (the ingredients)

REFORGE is a thin **conductor** on top of six existing tools. It does not fork or
merge them — it orchestrates them.

| Ingredient | Role in REFORGE |
| --- | --- |
| [`morluto/rea`](https://github.com/morluto/rea) | 🔎 **Eyes** — takes the target apart (behavior → binary) |
| [`affaan-m/everything-claude-code`](https://github.com/affaan-m/everything-claude-code) | 🧠 **Memory** + 🔒 **safety cage** |
| [`mattpocock/skills`](https://github.com/mattpocock/skills) | 🩹 **Guardrails** — patches agent mistakes |
| [`anthropics/skills`](https://github.com/anthropics/skills) | 📏 **Rulebook** — the skill standard everything follows |
| [`hesreallyhim/awesome-claude-code`](https://github.com/hesreallyhim/awesome-claude-code) | 📒 **Toolbox index** — pulls the right skill per target |
| [`obra/superpowers`](https://github.com/obra/superpowers) | ✅ **Discipline** — test-first rebuilding |

## The pipeline

```
          ┌──────────┐   ┌───────────┐   ┌─────────┐   ┌──────────┐
 TARGET → │ INSPECT  │ → │ UNDERSTAND│ → │  AUDIT  │ → │ REBUILD  │ → OUTPUTS
          │  (REA)   │   │ (memory)  │   │(security│   │(superpow.│
          └──────────┘   └───────────┘   │ + skills)│  │  + TDD)  │
                                          └─────────┘   └──────────┘
   governed throughout by: anthropics spec · mattpocock guardrails · awesome-cc index
```

1. **INSPECT** — REA takes the target apart.
2. **UNDERSTAND** — build a knowledge map of the target; save it to memory.
3. **AUDIT** — security skills flag weaknesses → `reports/`.
4. **REBUILD** *(optional)* — superpowers' test-first discipline produces a clean
   reimplementation → `src/`.

## Layout

```
reforge/
  docs/      design notes & architecture
  src/       the conductor + any rebuilt code
  targets/   things we analyze (git-ignored by default)
  reports/   security + teardown reports
```

## Status

🚧 Scaffold. Next step: wire in ingredient #1 (REA) and run a first real teardown
on a safe practice target.
