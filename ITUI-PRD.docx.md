

**ITUI**

Infisical Terminal UI

Product Requirements Document

Hackweek Project  |  v1.0

February 2025

| Field | Details |
| :---- | :---- |
| Project Name | ITUI – Infisical Terminal UI |
| Project Type | Hackweek Prototype |
| Target Users | Developers & DevOps Engineers |
| Platform | Cross-platform CLI (macOS, Linux, Windows) |
| Core Tech Stack | Go \+ Bubble Tea TUI framework \+ Claude AI API |
| Status | Draft |

# **1\. Executive Summary**

ITUI is an AI-powered terminal user interface that sits on top of the Infisical CLI. Instead of requiring users to know exact flag syntax, ITUI lets engineers type plain English prompts like show me all production secrets or compare staging vs prod \-- and the AI layer translates those prompts into Infisical CLI commands, executes them, and presents results in a rich interactive terminal UI.

The end state is a TUI where developers can prompt-engineer their way through Infisical without ever needing to look up documentation.

# **2\. Problem Statement**

## **2.1 Current Pain Points**

* The Infisical CLI has a broad command surface (secrets, auth, scan, export, run, agent, vault, etc.) that requires constant documentation lookup.

* Flags and options are numerous and non-obvious (--env, \--projectId, \--path, \--type, \--include-imports, etc.).

* There is no interactive exploration mode — every action requires a fully-formed command upfront.

* Switching between environments, projects, and paths requires mental tracking of context.

* New team members face a steep onboarding cliff before they can be productive with secrets management.

## **2.2 Opportunity**

LLMs are exceptionally good at translating natural language intent into structured CLI commands. By wrapping the Infisical CLI with an AI-mediated TUI, we can radically lower the barrier to entry while also speeding up power-user workflows through intelligent autocomplete, context awareness, and multi-step orchestration.

# **3\. Goals & Success Metrics**

| Goal | Metric | Target |
| :---- | :---- | :---- |
| Reduce time-to-first-action | Time from launch to first successful secret retrieval | \< 30 seconds for new user |
| Reduce CLI lookup friction | \# of documentation tab-switches during session | 0 for common tasks |
| High task completion via NL | % of natural language prompts that execute successfully | \> 85% on core commands |
| Positive demo reception | Hackweek audience vote or internal NPS | Top 3 project |
| Functional prototype | Core feature set working end-to-end | All P0 features shipped |

# **4\. User Personas**

## **4.1 The Developer (Primary)**

* Mid-level engineer who uses Infisical daily but never memorizes flag syntax.

* Wants to quickly fetch, update, or compare secrets across environments.

* Comfortable in the terminal but frustrated by documentation friction.

* Prompt: "Get me all secrets in staging that don't exist in prod"

## **4.2 The DevOps / Platform Engineer**

* Manages secrets at scale across many projects and environments.

* Needs to audit, rotate, and export secrets efficiently.

* Wants to script and automate but also explore interactively.

* Prompt: "Scan this repo for any hardcoded secrets and show me the results"

## **4.3 The New Team Member (Onboarding)**

* Just got Infisical access and doesn't know the CLI at all.

* Needs guardrails and discoverability — ITUI acts as an intelligent guide.

* Prompt: "What can I do here?" or "Show me the secrets for the backend service"

# **5\. Feature Specification**

## **5.1 Core Architecture**

ITUI is a standalone Go binary that launches an interactive terminal UI session. It maintains a persistent context (authenticated user, active project, active environment) and exposes a prompt interface backed by an AI model that maps natural language to Infisical CLI subcommands.

| Layer | Technology | Responsibility |
| :---- | :---- | :---- |
| TUI Framework | Bubble Tea (Go) | Rendering, keyboard input, pane management |
| AI Inference | Claude API (claude-sonnet-4-6) | NL → CLI command translation |
| CLI Execution | Infisical CLI (subprocess) | All actual Infisical operations |
| Config / State | Local config file \+ session state | Auth tokens, active context |
| Output Rendering | Lip Gloss (Go) | Colors, tables, formatting |

## **5.2 Feature Breakdown by Priority**

### **P0 — Must Ship (Hackweek Demo)**

| Feature | Description | Infisical Commands Mapped |
| :---- | :---- | :---- |
| AI Prompt Bar | Persistent input bar at the bottom of the TUI where users type natural language. AI translates to CLI commands and executes. | All |
| Context Panel | Persistent sidebar/header showing current: User, Project, Environment, Path | infisical user, infisical projects |
| Secret Browser | Scrollable, searchable list of secrets in the current context. Supports keyboard navigation. | infisical secrets get, infisical secrets list |
| Secret Detail View | On-select, expand a secret to show its value (masked by default), type, version, and last modified. | infisical secrets get \<name\> |
| Create / Update Secret | Prompted form (or natural language) to create or update a secret. | infisical secrets set \<key\>=\<value\> |
| Delete Secret | Confirmation dialog before deletion. | infisical secrets delete \<key\> |
| Environment Switcher | Quick-switch between environments (dev, staging, prod, etc.) with keyboard shortcut. | Context: \--env flag |
| Command Preview | Before executing AI-generated commands, show the exact CLI command that will run so users can learn and verify. | All — transparency layer |
| Output Pane | Scrollable output/results panel showing command stdout/stderr with syntax highlighting. | All |
| Authentication Flow | Detect if user is not logged in and guide them through login inline. | infisical login |

### **P1 — High Value (Stretch Goals)**

| Feature | Description |
| :---- | :---- |
| Multi-env Diff View | Side-by-side comparison of secrets across two environments. AI prompt: "diff staging and prod". |
| Secret Scanning | Trigger infisical scan on a provided path and display results inline with file \+ line references. |
| Export Modal | Export current secret set to .env, JSON, or YAML with format picker. |
| Import Secrets | Bulk import from a .env file, with conflict resolution UI. |
| Conversation History | Keep a scrollable log of all prompts \+ generated commands \+ results in the session. |
| Keyboard Shortcut Cheatsheet | Press '?' to show a modal of all keyboard shortcuts and common prompt examples. |
| Project Switcher | Browse and switch between Infisical projects without leaving the TUI. |

### **P2 — Future Vision**

| Feature | Description |
| :---- | :---- |
| Secret Rotation | AI-mediated secret rotation workflows with rollback safety. |
| Agent Config Builder | Visual editor for Infisical agent YAML config files. |
| Audit Log Viewer | Browse the secret access audit log from within the TUI. |
| Dynamic Secret Support | Request and view dynamic secrets (DB credentials, cloud tokens) via TUI. |
| Team / Access Management | View and manage project member permissions. |
| Folder / Path Navigator | Tree-view navigation of secret folder hierarchy. |

# **6\. AI Prompt System Design**

## **6.1 How It Works**

When a user types a natural language prompt, ITUI sends the following context to the Claude API:

* System prompt: Defines ITUI's role as an Infisical CLI command translator, provides full CLI command reference, current session context (project, env, path), and safety rules.

* User message: The raw natural language prompt from the user.

* Claude responds with: (a) the exact Infisical CLI command(s) to run, (b) a plain-English explanation of what will happen, and (c) a safety classification (read-only vs. destructive).

## **6.2 Prompt Examples & Expected Command Mappings**

| User Prompt | Generated CLI Command | Action Type |
| :---- | :---- | :---- |
| Show me all production secrets | infisical secrets get \--env=prod | Read |
| Set DATABASE\_URL to postgres://... in staging | infisical secrets set DATABASE\_URL='postgres://...' \--env=staging | Write |
| Delete the old API key in dev | infisical secrets delete OLD\_API\_KEY \--env=dev | Destructive |
| Compare secrets between staging and prod | infisical secrets get \--env=staging \+ infisical secrets get \--env=prod (diff) | Read |
| Scan my current directory for leaked secrets | infisical scan . | Read |
| Export all dev secrets as a .env file | infisical export \--env=dev \--format=dotenv | Read |
| Who am I logged in as? | infisical user | Read |
| Run my app with prod secrets injected | infisical run \--env=prod \-- \<user\_provides\_command\> | Read |
| Show me secrets under /backend/database | infisical secrets get \--env=prod \--path=/backend/database | Read |
| What can I do here? | (No command — AI explains TUI capabilities) | Meta |

## **6.3 Safety Gates**

* All destructive operations (set, delete, rotate) require a confirmation prompt showing the exact command before execution.

* The AI is instructed to always classify commands as read-only or destructive and surface that classification to the user.

* Production environment operations get an additional visual warning banner.

* The user can press Escape to cancel any pending command before it runs.

# **7\. UX & Interface Design**

## **7.1 Layout**

The TUI is divided into four persistent regions:

┌─────────────────────────────────────────────────────┐  
│  ITUI  |  Project: backend-api  |  Env: production   │  ← Context Bar  
├────────────────────────┬────────────────────────────┤  
│  Secret Browser        │  Output / Detail Pane      │  ← Main Content  
│  \> DATABASE\_URL   ████ │  Key:   DATABASE\_URL       │  
│    API\_KEY        ████ │  Value: ●●●●●●●●  \[reveal\] │  
│    REDIS\_URL      ████ │  Env:   production         │  
│    JWT\_SECRET     ████ │  Path:  /                  │  
├────────────────────────┴────────────────────────────┤  
│  🤖 Prompt: show me all secrets that start with DB\_  │  ← AI Prompt Bar  
│  ⌨ Will run: infisical secrets get \--env=prod        │  ← Command Preview  
└─────────────────────────────────────────────────────┘

## **7.2 Keyboard Shortcuts**

| Key | Action |
| :---- | :---- |
| Tab / Shift+Tab | Switch focus between panes |
| ↑ / ↓ | Navigate secret list |
| Enter | Select / expand secret detail |
| / or Ctrl+F | Focus search / filter in secret browser |
| e | Switch environment (opens picker) |
| p | Switch project |
| n | New secret (opens creation form) |
| d | Delete selected secret (with confirmation) |
| r | Reveal / mask secret value |
| Ctrl+E | Export secrets (opens format picker) |
| Ctrl+P | Focus AI prompt bar |
| ? | Open help / cheatsheet modal |
| q / Ctrl+C | Quit ITUI |

# **8\. Technical Specification**

## **8.1 Tech Stack**

| Component | Technology | Notes |
| :---- | :---- | :---- |
| Language | Go 1.22+ | Same as Infisical CLI — easy to co-locate |
| TUI Framework | Bubble Tea (Charm) | Component model, event loop, composable views |
| Styling | Lip Gloss (Charm) | Color themes, borders, layout primitives |
| Spinners / Progress | Bubbles (Charm) | Pre-built TUI components |
| AI Integration | Anthropic Claude API | claude-sonnet-4-6, \~1000 token responses |
| CLI Execution | os/exec (Go stdlib) | Subprocess calls to infisical binary |
| Config Storage | \~/.itui/config.toml | Session state, API key, preferences |
| Fuzzy Search | go-fuzzyfinder or sahilm/fuzzy | Secret list filtering |

## **8.2 Key Go Modules**

* github.com/charmbracelet/bubbletea — TUI framework

* github.com/charmbracelet/lipgloss — styling

* github.com/charmbracelet/bubbles — text inputs, spinners, tables, viewports

* github.com/anthropics/anthropic-sdk-go — Claude API client

* github.com/spf13/viper — config management

## **8.3 System Prompt Design**

The AI system prompt is the backbone of ITUI's intelligence. It will include:

* Role definition: "You are an assistant embedded in ITUI, a terminal UI for Infisical. Your job is to translate user natural language prompts into exact Infisical CLI commands."

* Full Infisical CLI command reference (injected at runtime).

* Current session context (project ID, environment, path, logged-in user).

* Response format spec: JSON with fields: command (string or array), explanation (string), action\_type (read | write | destructive), requires\_confirmation (bool).

* Safety rules: Never generate commands that bypass authentication. Always flag destructive operations. Ask clarifying questions if intent is ambiguous.

## **8.4 Command Execution Model**

All Infisical CLI calls are made via subprocess (exec.Command). ITUI captures stdout and stderr separately. Results are streamed into the Output pane in real time. For destructive commands, execution is held pending user confirmation (Y/n). ITUI never directly calls the Infisical API — it only shells out to the existing CLI binary to ensure auth, caching, and behavior parity.

# **9\. Hackweek Execution Plan**

| Day | Focus | Deliverables |
| :---- | :---- | :---- |
| Day 1 — Morning | Setup & Scaffolding | Go project init, Bubble Tea hello world, basic layout with 3 panes |
| Day 1 — Afternoon | Core TUI Layout | Context bar, secret browser pane with dummy data, output pane, keyboard nav |
| Day 2 — Morning | Infisical CLI Integration | subprocess execution, real secret list, env switcher, secret detail view |
| Day 2 — Afternoon | AI Prompt Bar | Claude API integration, NL → command translation, command preview strip |
| Day 3 — Morning | Write Operations | Create, update, delete secrets via prompt and keyboard shortcuts |
| Day 3 — Afternoon | Polish \+ P1 Features | Multi-env diff, scan view, styling, help modal |
| Day 4 | Demo Prep | End-to-end run-through, fix critical bugs, record demo video |

# **10\. Risks & Mitigations**

| Risk | Likelihood | Impact | Mitigation |
| :---- | :---- | :---- | :---- |
| AI generates incorrect CLI commands | Medium | High | Command preview pane \+ confirmation step. Constrain system prompt with exact CLI reference. |
| Infisical CLI output format changes | Low | Medium | Pin to known CLI version in dev. Parse JSON output flags where available. |
| TUI rendering issues on Windows | Medium | Low | Primarily target macOS/Linux for hackweek. Windows is P2. |
| API latency makes AI feel slow | Medium | Medium | Show a spinner immediately. Use streaming response if possible. Cache common translations. |
| Auth token management complexity | Low | High | Delegate entirely to infisical CLI — ITUI never handles tokens directly. |
| Scope creep during hackweek | High | High | Hard cut: P0 features only for Days 1-3. P1 only if P0 is fully green. |

# **11\. Out of Scope (Hackweek)**

* Direct Infisical API calls (all operations go through the CLI binary).

* Full Windows support (TUI rendering varies — nice to have post-hackweek).

* Multi-user collaboration features.

* CI/CD pipeline integration or agent mode from within ITUI.

* Custom theme / color scheme configuration.

* Plugin or extension system.

# **12\. Appendix: Infisical CLI Command Reference**

Key commands that ITUI will map natural language to:

| Command | Description |
| :---- | :---- |
| infisical login | Authenticate with Infisical Cloud or self-hosted instance |
| infisical user | Display current authenticated user info |
| infisical projects | List available projects |
| infisical secrets get \[--env\] \[--path\] \[--projectId\] | List/get secrets in current context |
| infisical secrets set KEY=VALUE \[--env\] \[--path\] | Create or update a secret |
| infisical secrets delete KEY \[--env\] \[--path\] | Delete a secret by key |
| infisical export \[--env\] \[--format=dotenv|json|yaml\] | Export secrets to a file format |
| infisical run \[--env\] \-- \<command\> | Inject secrets into a subprocess as env vars |
| infisical scan \[path\] | Scan directory/git history for hardcoded secrets |
| infisical agent \--config=\<file\> | Start the Infisical agent with a config file |
| infisical vault \[set|get\] | Manage vault backend configuration |

*— End of Document —*