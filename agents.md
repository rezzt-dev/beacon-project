# BEACON-PROJECT: REPOSITORY GUIDE

local network inventory and monitoring tool with cli, live web app and standalone reports. this guide covers the repository; nested agent instructions apply within their own folders.

## PROJECT OVERVIEW

| property | verified value |
| --- | --- |
| repository | `rezzt-dev/beacon-project` |
| active source | `./` |
| development base for this change | `main` |
| remote default branch | `main` |
| version source | `pyproject.toml` |
| continuous integration | `.github/workflows/ci.yml` |

## TECHNOLOGY STACK

- python dependencies and package entry points are declared per program; no shared environment is assumed

## PROJECT STRUCTURE

- `app/`
- `changelog.md`
- `license.md`
- `pyproject.toml`
- `readme.md`
- `scripts/`
- `tests/`
- `uv.lock`

management documentation lives in `.docs/manager.md`, `.docs/-github-guides/` and `.docs/repo-audit-and-fix.md`. keep this file and `claude.md` consistent.

## BUILD, RUN AND TEST COMMANDS

for application changes, run these checks from `./`:

```bash
uv run pytest
uv run ruff check .
```

## MODULE RESPONSIBILITIES

| path | responsibility |
| --- | --- |
| `app/beacon/cli/` | typer command surface |
| `app/beacon/scanners/` | discovery and protocol adapters |
| `app/beacon/core/` | shared domain logic |
| `app/beacon/services/` | application services |
| `app/beacon/storage/` | persisted inventory |
| `app/beacon/web/` | live app, jobs, streaming and authentication |
| `app/beacon/web/static/` | shipped browser assets, without a node build |
| `app/beacon/export/` | standalone report generation and bundled assets |
| `tests/` | automated regression coverage |

keep cli, live views and exports consistent when changing shared inventory fields. use the existing web security layer for session and request protection. reports are portable copies of observations: review personal and network information before sharing them. browser checks require the optional browser dependencies and an installed playwright browser.

## CODE STYLE AND ARCHITECTURAL DECISIONS

distinguish observations from inferences; use simulated network fixtures; never scan a network or expose real device data merely to validate documentation. follow the existing formatter and naming of the changed module. verify manifest versions when dependencies change.

## TESTING STRATEGY

documentation-only changes require `git diff --check`, existing-path checks and a review of the staged file list. run module checks for application changes, with disposable data. report unavailable tooling and failed checks; never claim a check passed without running it.

## SECURITY AND DEPLOYMENT

keep credentials, local configuration, signing material and user data out of commits. do not print secret values while auditing. inspect configuration names and code references instead.

existing legal and community files: `license.md`. when changing dependencies, permissions, storage or network services, review those files against the implementation. record missing policies as audit work; do not invent licence terms or ownership decisions.

deployment, signing, store publication, migrations against hosted databases and repository settings require their own explicit request. this documentation task prepares management instructions and pull requests.

## COMMON TASKS

1. read the relevant module and its nearest agent instructions
2. inspect the working tree and choose the smallest change that solves the request
3. update the affected documentation and changelog with evidence from the diff
4. run checks appropriate to the changed module and report their actual results
5. for git operations, follow the manager and the digest below

## COMMIT, PR, MERGE & RELEASE GUIDELINES

read `.docs/manager.md` first, then the selected guide in `.docs/-github-guides/`. these files are versioned; this digest also works without opening them.

| request | guide |
| --- | --- |
| commit title, body and changelog | `commit-guide.md`, `changelog-guide.md` |
| pull request or merge | `pr-merge-guide.md`, `branching-guide.md` |
| version and release | `release-guide.md`, `changelog-guide.md` |
| permissions and sensitive data | `agent-rules.md` |

- inspect `git status`, both diffs and recent history before describing changes
- use `<prefix> | <imperative summary>` with `update`, `fix`, `hotfix`, `changes` or `changelog`; keep titles within 72 characters
- write commit bodies as 2 to 6 markdown bullets, one logical change per line, with literal paths in backticks
- never add authorship footers, automated attribution, signatures or generation notices; preserve the configured git identity
- update `changelog.md` under `## SIN PUBLICAR / UNRELEASED` in matching `### CASTELLANO` and `### ENGLISH` sections
- use the existing changelog category vocabulary and preserve language parity; describe only changes in the actual diff
- summarize pull requests in 1 to 3 bullets per category and language, at most 110 characters per bullet
- documentation and repository-management work targets `main`; the remote default is `main`; do not silently promote development work to the default branch
- the authorization for a requested action remains valid throughout that task; creating a pull request includes pushing its branch, but does not authorize merging or publishing
- use merge commits when a merge is requested; never force-push, rewrite published history or remove branches without an explicit instruction
- releases use the approved version and an immutable tag on the verified release commit, with english notes from the closed changelog; do not create a release for documentation work
- deliver requested titles, bodies and changelog fragments in separate code blocks; report executed actions with their commit hash or pull request link
