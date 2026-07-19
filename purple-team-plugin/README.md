# Purple Team Workflow — Claude Code Plugin

`purple-team-workflow` packages an end-to-end purple team loop for Claude Code:
**threat intel → simulation planning → detection analysis → SIEM validation → reporting → tracking.**

It bundles three slash commands, one subagent, a Hayabusa MCP server configuration,
and a project `CLAUDE.md` template.

## Contents

```
purple-team-plugin/
├── plugin.json                    # plugin manifest
├── commands/
│   ├── ingest-ti.md               # /ingest-ti
│   ├── query.md                   # /query
│   └── purple-loop.md             # /purple-loop
├── agents/
│   └── atomic-mapper.md           # atomic-mapper subagent
├── skills/
│   └── detection-engineering/     # Sigma rule standards + validator
│       ├── SKILL.md
│       ├── scripts/validate-rule.py
│       └── references/            # severity guide, FP patterns, example rules
├── mcp/
│   └── server-configs.json        # hayabusa MCP server definition
└── templates/
    └── CLAUDE.md                  # drop-in project guidance
```

## Dependencies

### External tools (install separately)
| Tool | Purpose | Install |
|------|---------|---------|
| **hayabusa** | EVTX scanning / Sigma-based detection | [Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa) releases, or the wrapper repo below |
| **defuddle-cli** | Clean article extraction for `/ingest-ti` | `npm install -g defuddle-cli` |

`/ingest-ti` degrades gracefully if `defuddle` is missing (falls back to `WebFetch` or a paste prompt).

### MCP servers
| Server | Provides | Notes |
|--------|----------|-------|
| **hayabusa** | `scan_evtx` tool + Sigma/ATT&CK rule resources | Python MCP server wrapping the Hayabusa CLI. Requires Python 3, the `mcp` and `PyYAML` packages, and a local `hayabusa.exe`. |

## Installation

> This is a directory-style plugin (a `plugin.json` manifest with `commands/`,
> `agents/`, `mcp/`, `templates/` folders). Install it however your Claude Code
> setup consumes local plugins — the manual layout below always works.

### Manual install (works everywhere)
1. **Commands** — copy `commands/*.md` into your project's `.claude/commands/`
   (or `~/.claude/commands/` for all projects).
2. **Agent** — copy `agents/atomic-mapper.md` into `.claude/agents/`.
3. **MCP server** — copy `mcp/server-configs.json` to your project root as `.mcp.json`
   (or merge its `mcpServers` block into an existing `.mcp.json`).
   ⚠️ **Edit the path first** — `server-configs.json` points at an absolute path to
   `server.py`. Update it to wherever your Hayabusa MCP server lives on this machine.
4. **Trust the server** — add to `.claude/settings.json`:
   ```json
   { "enabledMcpjsonServers": ["hayabusa"] }
   ```
5. **Skill** — copy `skills/detection-engineering/` into `.claude/skills/`
   (or `~/.claude/skills/`). Claude activates it automatically when writing or
   reviewing Sigma rules.
6. **Project template** — copy `templates/CLAUDE.md` to your project root as `CLAUDE.md`.
7. **Restart Claude Code** so `.mcp.json` loads, then run `/mcp` to confirm `hayabusa` is connected.

### Verify
```
/ingest-ti <url>     # should fetch + extract TTPs
/mcp                 # hayabusa listed as connected
```

## Commands

| Command | What it does |
|---------|--------------|
| **`/ingest-ti <url\|text>`** | Ingests a threat-intel report (URL via `defuddle`, or pasted content), extracts TTPs, maps them to MITRE ATT&CK IDs with confidence + kill-chain phase, and produces a simulation plan flagging what's safe to run in a lab. |
| **`/query <search>`** | Translates a request into SIEM query syntax (Splunk SPL by default; KQL/others on request), runs it via a SIEM MCP if available (otherwise emits the query for manual run), maps results to ATT&CK, and generates Obsidian-compatible `[[backlink]]` investigation notes. |
| **`/purple-loop`** | Orchestrates the full 8-step exercise — intel → test planning (`atomic-mapper`) → execution checklist → detection analysis (`hayabusa`) → SIEM validation (`/query`) → gap analysis → documentation → Vectr tracking — summarizing progress at each transition. |

## Agents

| Agent | What it does |
|-------|--------------|
| **`atomic-mapper`** | Takes a list of ATT&CK technique IDs and maps each to executable **Atomic Red Team** tests (Windows-focused). Returns `Invoke-AtomicTest` + cleanup commands, prerequisites, and expected telemetry (Sysmon + Windows Security Event IDs), prioritizing tests with minimal prereqs and clear telemetry. |

## Skills

| Skill | What it does |
|-------|--------------|
| **`detection-engineering`** | Team standards for hand-authored **Sigma rules** — enforces ATT&CK technique tagging, justified severity, false-positive handling, and completeness. Activates automatically when writing/reviewing detection rules or working with `rules/*.yml`. Ships `scripts/validate-rule.py` plus reference material (`severity-guide.md`, `false-positive-patterns.md`, and an example rule). |

## Declared-but-not-bundled

`plugin.json` declares `hooks: true`, but **no hooks are included** in this version —
the flag is reserved in the manifest for a future release. Everything else the manifest
declares (the `detection-engineering` skill, the three commands, the `atomic-mapper`
agent, and the `hayabusa` MCP config) is present and backed by real content.

## MCP server-config note

`mcp/server-configs.json` mirrors the project's `.mcp.json`:
```json
{
  "mcpServers": {
    "hayabusa": {
      "type": "stdio",
      "command": "python",
      "args": ["C:/Users/fayee/mcp-hayabusa/server.py"]
    }
  }
}
```
The `args` path is machine-specific — change it to your checkout of the Hayabusa MCP
server before use. If `python` isn't on `PATH`, replace `"python"` with a full
interpreter path (e.g. a venv's `python.exe`).

## License / attribution
Author: Fayeeka. Bundles configuration for third-party tools (Hayabusa, Atomic Red
Team, defuddle) that carry their own licenses.
