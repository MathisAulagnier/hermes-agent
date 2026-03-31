---
name: qwen-code
description: Delegate coding tasks to Qwen Code CLI (open-source terminal AI agent). Equivalent to claude-code but free/open-source with OpenRouter support. Use for code generation, refactoring, debugging, code review, and agentic workflows.
version: 1.0.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [coding, qwen, CLI, agent, openrouter, BMAD]
    related_skills: [claude-code, codex, opencode]
---

# Qwen Code — Terminal AI Agent

Qwen Code is an **open-source AI agent for the terminal**, optimized for the Qwen3-Coder model family. It provides a Claude Code-like experience with full agentic workflow capabilities, but it's **free, open-source, and supports OpenRouter**.

## When to Use

- User asks for code generation, refactoring, or debugging
- Need automated code reviews or test generation
- Working in headless/CI environments (no browser needed)
- Want multi-provider support (OpenRouter, OpenAI, Anthropic, Gemini)
- Prefer free tier (1000 req/day with Qwen OAuth) or BYOK (bring your own key)
- Need PTY-based sandboxed execution with auto-approval modes

## Prerequisites

```bash
# Install Node.js 20+ and qwen CLI
node --version  # should be v20+
npm install -g @qwen-code/qwen-code@latest

# Verify installation
qwen --version  # 0.13.2+
```

### Authentication (choose one)

| Method | Setup | Best for |
|--------|-------|----------|
| **Qwen OAuth** (free) | `qwen` then `/auth` → browser login | Interactive sessions, 1000 req/day |
| **OpenRouter API key** (headless) | `export OPENROUTER_API_KEY="sk-or-..."` | Server/CI, unlimited (paid) |
| **Any OpenAI-compatible** | Edit `~/.qwen/settings.json` | Custom endpoints (Ollama, vLLM, etc.) |

## Quick Reference

### One-Shot Code Generation

```python
# Using terminal tool directly (for simple tasks)
terminal(command="qwen -p 'Write a FastAPI endpoint with JWT auth' --yolo", workdir="~/project", pty=true)
```

### Background Mode (Long Tasks)

```python
# Start in background with PTY
terminal(command="qwen -p 'Refactor the auth module to use OAuth2' --yolo", workdir="~/project", background=true, pty=True)
# Monitor
process(action="poll", session_id="<id>")
process(action="log", session_id="<id>")
```

### PR Reviews

```python
terminal(command="cd /tmp/review && git clone https://github.com/user/repo.git . && gh pr checkout 42 && qwen -p 'Review this PR against main. Check for bugs, security issues, and style.' --yolo", pty=true)
```

### Parallel Work

```python
terminal(command="qwen -p 'Fix the login bug' --yolo", workdir="/tmp/issue-1", background=true, pty=true)
terminal(command="qwen -p 'Add unit tests for auth' --yolo", workdir="/tmp/issue-2", background=true, pty=true)
process(action="list")
```

## Key Flags

| Flag | Effect |
|------|--------|
| `qwen -p "prompt"` | One-shot task, exits when done |
| `--yolo` | Auto-approve all file changes (no confirmation) |
| `--model <id>` | Use specific model (e.g. `qwen/qwen3-coder`) |
| `--workdir <dir>` | Set working directory |
| `-i` | Interactive mode (multi-turn) |
| `--system-prompt <text>` | Override system prompt (for BMAD agents) |

## Rules

1. **Always use `pty=true`** — Qwen Code is an interactive terminal app and will hang without a PTY.
2. **Use `workdir`** — Keep the agent focused on the right directory.
3. **Background for long tasks** — Use `background=true` and monitor with `process` tool.
4. **Don't interfere** — Monitor with `poll`/`log`, don't kill slow sessions.
5. **Report results** — After completion, check what changed and summarize for the user.
6. **Prefer headless mode** — For delegation, use `-p` flag instead of interactive mode.

## Integration with BMAD Method

Qwen Code's LLM-agnostic architecture supports BMAD agent personas via system prompts:

```bash
# Run a BMAD agent role
qwen -p "Analyze requirements for a todo API" \
  --system-prompt "You are the BMAD Analyst (Mary). You are analytical, detail-oriented. Your job: transform user needs into clear specs." \
  --yolo
```

Or chain multiple roles:

```bash
# Analyst → Architect → Dev
qwen -p "$(cat brief.md)" --system-prompt "$(cat bmad-analyst.md)" --yolo
# Capture output → feed to next agent
```

## Provider Configuration (Advanced)

Edit `~/.qwen/settings.json` to add custom providers:

```json
{
  "modelProviders": {
    "openai": [
      {
        "id": "qwen/qwen3-coder",
        "name": "Qwen3 Coder via OpenRouter",
        "baseUrl": "https://openrouter.ai/api/v1",
        "envKey": "OPENROUTER_API_KEY",
        "generationConfig": {
          "timeout": 300000,
          "contextWindowSize": 256000,
          "samplingParams": {
            "temperature": 0.3,
            "max_tokens": 8192
          }
        }
      }
    ]
  },
  "model": { "name": "qwen/qwen3-coder" },
  "security": { "auth": { "selectedType": "openai" } }
}
```

## Troubleshooting

| Error | Solution |
|-------|----------|
| `No auth type is selected` | Set `OPENROUTER_API_KEY` or run `qwen auth qwen-oauth` |
| `Qwen Code CLI not found` | `npm install -g @qwen-code/qwen-code@latest` |
| `Command hangs` | Add `pty=true` to terminal call |
| `Model not found` | Check `~/.qwen/settings.json` and `/model` list |
| `Sandbox permission denied` (macOS) | Use `--yolo` or set `"tools.sandbox": false` in settings |
| Rate limit (OAuth) | Wait 24h or switch to OpenRouter API key |

## Examples

**Create a Python CLI calculator:**
```bash
qwen -p "Build a CLI calculator in Python with add/subtract/multiply/divide operations, error handling, and tests." --yolo
```

**Refactor existing code:**
```bash
cd ~/myproject
qwen -p "Refactor the database module to use asyncpg and connection pooling." --yolo
```

**Explain a codebase:**
```bash
qwen -p "Provide an architecture overview and explain the main modules." --yolo
```

**Generate tests:**
```bash
qwen -p "Write pytest unit tests for all functions in src/auth.py with mocks for external services." --yolo
```
