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

The CLI is [open-source](https://github.com/QwenLM/qwen-code) (MIT, TypeScript) and supports interactive sessions, non-interactive one-shots, multi-provider authentication (Qwen OAuth, OpenRouter, OpenAI-compatible), PTY-based sandboxed execution, and auto-approval modes.

## Prerequisites

- Node.js 20+ installed
- Qwen Code installed: `npm install -g @qwen-code/qwen-code@latest`
- Authenticated: see Authentication section below
- Use `pty=true` in terminal calls — Qwen Code is an interactive terminal app

### Authentication (choose one)

| Method | Setup | Best for |
|--------|-------|----------|
| **Qwen OAuth** (free) | Run `qwen` then use `/auth` command to log in | Interactive sessions, 1000 req/day free tier |
| **OpenRouter API key** (headless) | `export OPENROUTER_API_KEY="sk-or-..."` | Server/CI, unlimited (paid) |
| **Any OpenAI-compatible** | Edit `~/.qwen/settings.json` to add custom providers | Custom endpoints (Ollama, vLLM, etc.) |

## One-Shot Tasks

```
terminal(command="qwen -p 'Add JWT authentication with refresh tokens to the Express API' --yolo", workdir="/path/to/project", pty=true)
```

For quick scratch work:
```
terminal(command="cd $(mktemp -d) && git init && qwen -p 'Build a REST API for todos with SQLite' --yolo", pty=true)
```

## Background Mode (Long Tasks)

For tasks that take minutes, use background mode so you can monitor progress:

```
# Start in background with PTY
terminal(command="qwen -p 'Refactor the auth module to use OAuth 2.0' --yolo", workdir="~/project", background=true, pty=true)
# Returns session_id

# Monitor progress
process(action="poll", session_id="<id>")
process(action="log", session_id="<id>")

# Send input if Qwen Code asks a question
process(action="submit", session_id="<id>", data="yes")

# Kill if needed
process(action="kill", session_id="<id>")
```

## PR Reviews

Clone to a temp directory to avoid modifying the working tree:

```
terminal(command="REVIEW=$(mktemp -d) && git clone https://github.com/user/repo.git $REVIEW && cd $REVIEW && gh pr checkout 42 && qwen -p 'Review this PR against main. Check for bugs, security issues, and code quality.' --yolo", pty=true)
```

Or use git worktrees:
```
terminal(command="git worktree add /tmp/pr-42 pr-42-branch", workdir="~/project")
terminal(command="qwen -p 'Review the changes in this branch vs main' --yolo", workdir="/tmp/pr-42", pty=true)
```

## Parallel Work

Spawn multiple Qwen Code instances for independent tasks:

```
terminal(command="qwen -p 'Fix the login bug' --yolo", workdir="/tmp/issue-1", background=true, pty=true)
terminal(command="qwen -p 'Add unit tests for auth' --yolo", workdir="/tmp/issue-2", background=true, pty=true)

# Monitor all
process(action="list")
```

## Session Commands

During an interactive session, use these commands:

| Command | Effect |
|---------|--------|
| `/auth` | Manage authentication (Qwen OAuth, API keys) |
| `/model` | List and switch available models |
| `/compress` | Shrink conversation history to save tokens |
| `/clear` | Wipe history and start fresh |
| `/copy` | Copy last assistant message to clipboard |
| `Ctrl+C` | Cancel current operation |

## Key Flags

| Flag | Effect |
|------|--------|
| `qwen -p "task"` | Non-interactive one-shot execution |
| `--yolo` | Auto-approve all actions (no confirmation prompts) |
| `--model <id>` | Use specific model (e.g. `qwen/qwen3-coder`) |
| `--workdir <dir>` | Set working directory |
| `-i` | Interactive mode (multi-turn chat) |
| `--system-prompt <text>` | Override system prompt (for custom agents/BMAD) |

## Rules

1. **Always use `pty=true`** — Qwen Code is an interactive terminal app and will hang without a PTY
2. **Use `workdir`** — keep the agent focused on the right directory
3. **Background for long tasks** — use `background=true` and monitor with `process` tool
4. **Don't interfere** — monitor with `poll`/`log`, don't kill sessions because they're slow
5. **Report results** — after completion, check what changed and summarize for the user
6. **Prefer headless mode** — for delegation, use `-p` flag instead of interactive mode
7. **Check prerequisites** — verify `qwen` CLI is installed before attempting delegation

## Integration with BMAD Method

Qwen Code's LLM-agnostic architecture supports BMAD agent personas via system prompts:

```
qwen -p "Analyze requirements for a todo API" \
  --system-prompt "You are the BMAD Analyst. You are analytical, detail-oriented. Your job: transform user needs into clear specs." \
  --yolo
```

Or chain multiple roles using output redirection:
```
qwen -p "Analyze: $(cat brief.md)" --system-prompt "You are the BMAD Analyst." --yolo > analysis.md
qwen -p "Design architecture from: $(cat analysis.md)" --system-prompt "You are the BMAD Architect." --yolo > design.md
```

## Provider Configuration (Advanced)

Edit `~/.qwen/settings.json` to add custom OpenAI-compatible providers:

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
| `No auth type is selected` | Set `OPENROUTER_API_KEY` or run `qwen` then `/auth` to configure Qwen OAuth |
| `Qwen Code CLI not found` | `npm install -g @qwen-code/qwen-code@latest` |
| `Command hangs` | Add `pty=true` to the terminal call |
| `Model not found` | Check `~/.qwen/settings.json` and use `/model` in interactive mode to list available models |
| `Sandbox permission denied` (macOS) | Use `--yolo` or set `"tools.sandbox": false` in settings |
| Rate limit (OAuth free tier) | Wait 24 hours or switch to OpenRouter API key for unlimited usage |

## Examples

**Create a Python CLI calculator:**
```
qwen -p "Build a CLI calculator in Python with add/subtract/multiply/divide operations, error handling, and tests." --yolo
```

**Refactor existing code:**
```
cd ~/myproject
qwen -p "Refactor the database module to use asyncpg and connection pooling." --yolo
```

**Explain a codebase:**
```
qwen -p "Provide an architecture overview and explain the main modules." --yolo
```

**Generate tests:**
```
qwen -p "Write pytest unit tests for all functions in src/auth.py with mocks for external services." --yolo
```
