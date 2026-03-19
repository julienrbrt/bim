# EVM Exploit Hunter

> [!WARNING]
> ~80% AI-generated. Always verify findings manually before acting on them.

AI-powered smart contract security agent for EVM chains. Discovers newly verified contracts via [Sourcify](https://docs.sourcify.dev/docs/intro), analyzes their source code with Gemini, and generates bug bounty reports with Foundry PoC exploits — all from a chat-driven terminal UI.

Built with the [Google ADK for Go](https://google.github.io/adk-docs/get-started/go/) and [Bubbletea v2](https://charm.land/bubbletea).

## How it works

```
Sourcify API → Discovery → Analyzer (LLM) → Reporter (LLM)
                  ↓              ↓                ↓
               SQLite       skip/findings     Markdown report
                                               + Foundry PoC
```

1. **Discovery** — polls Sourcify for newly verified contracts and stores them as `pending` in SQLite.
2. **Analyzer** — skips known-safe contracts (OZ interfaces and stateless libraries), resolves protocol dependencies (proxy implementations, oracles, pools, routers) from Sourcify, then runs single-pass or two-pass LLM analysis with the full interaction context. Outputs findings by severity.
3. **Reporter** — for Critical/High findings, generates a Markdown bug bounty report with a Foundry PoC and recommended fix.

The whole pipeline runs autonomously in the background, or you can drive it manually from the chat.

## Setup

**Prerequisites:** Go 1.26+, [Google Gemini API key](https://aistudio.google.com/app/apikey)

```sh
go install github.com/julienrbrt/exploithunter@main
cp config.example.yaml config.yaml   # then fill in google_api_key
exploithunter -c config.yaml
```

## Configuration

All fields have sensible defaults except `google_api_key`. Key options:

```yaml
google_api_key: "YOUR_KEY" # required
model_name: gemini-2.5-pro # Gemini model to use
poll_interval: 60s # how often to poll Sourcify
max_single_pass_tokens: 200000 # threshold for two-pass analysis
log_level: info # debug | info | warn | error
data_dir: ./data # reports + SQLite database

chains:
  - id: 1
    name: Ethereum Mainnet
    rpc_url: https://eth.llamarpc.com
  - id: 8453
    name: Base
    rpc_url: https://mainnet.base.org

# Optional: extend the skip list (case-insensitive name substrings).
# Defaults cover all OZ interfaces and stateless libraries.
# skipped_contracts:
#   - MyInternalHelper
```

## Agent tools

| Tool                 | Description                                           |
| -------------------- | ----------------------------------------------------- |
| `run_pipeline`       | Full discover → analyze → report pipeline             |
| `discover_contracts` | Trigger an immediate discovery cycle                  |
| `analyze_contract`   | Analyze a specific contract by chain ID + address     |
| `reanalyze_contract` | Force re-analysis of a previously analyzed contract   |
| `generate_report`    | Generate a bug bounty report + PoC for a finding      |
| `generate_poc`       | Generate only the Foundry PoC for a finding           |
| `display_report`     | Print a previously generated report                   |
| `list_contracts`     | List tracked contracts, filter by status and/or chain |
| `discovery_status`   | Check background discovery loop status                |

## Analysis skills

Skills are domain-specific knowledge files injected into the system prompt, adapted from [Trail of Bits](https://github.com/trailofbits/skills):

`entry-point-analyzer` · `token-integration-analyzer` · `token-assessment-categories` · `variant-analysis` · `false-positive-patterns` · `guidelines-advisor` · `audit-prep`
