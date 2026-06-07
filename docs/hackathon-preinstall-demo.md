# Hackathon Pre-Install Demo

This is the local fallback demo for Microsoft Build AI 2026, Security in the
Agentic Future. It demonstrates the same policy behavior without requiring a
live Microsoft tenant.

Run it from:

```bash
cd demo/agent-workspace
```

The point of the demo is concrete: an AI coding agent recommends a package, the
agent attempts `npm install`, and Pounce Sentinel checks the dependency before
`npm` executes.

To route normal npm commands through Pounce in this terminal session, wrap `npm`:

```bash
npm() { "$PWD/../../scripts/pounce-npm" "$@"; }
```

Then the agent-visible command stays normal:

```bash
npm install event-stream@3.3.7
```

## Demo Script

Use dry-run mode first so the demo is repeatable and does not depend on npm
network timing:

```bash
export POUNCE_NPM_DRY_RUN=1
export POUNCE_ACTOR=foundry-coding-agent
export POUNCE_REPOSITORY=contoso/agentic-checkout
```

To run the whole dry-run sequence from the repository root:

```bash
bash scripts/demo-agent-preinstall.sh
```

### 1. Safe Recommendation

Narration:

> The agent recommends `lodash@4.17.21`. Pounce checks the exact release before
> installation.

Command:

```bash
../../scripts/pounce-npm install lodash@4.17.21
```

With the wrapper function active:

```bash
npm install lodash@4.17.21
```

Expected result: Pounce returns `ALLOW`, then says npm would continue.

### 2. Floating Version Warning

Narration:

> The agent asks for a floating version. This is not malicious, but it is not
> safe enough for governed agentic installs.

Command:

```bash
../../scripts/pounce-npm install lodash@^4.17.0
```

With the wrapper function active:

```bash
npm install lodash@^4.17.0
```

Expected result: Pounce returns `WARN` and recommends an exact version.

### 3. Risky Dependency Block

Narration:

> The agent recommends a known risky package. Pounce blocks it before the
> package reaches `node_modules` or `package.json`.

Command:

```bash
../../scripts/pounce-npm install event-stream@3.3.7
```

With the wrapper function active:

```bash
npm install event-stream@3.3.7
```

Expected result: Pounce returns `BLOCK` and exits before npm is executed.

### 4. Direct Manifest Bypass Attempt

Replace `demo/agent-workspace/package.json` temporarily with:

```json
{
  "name": "pounce-agent-demo-workspace",
  "version": "0.1.0",
  "private": true,
  "dependencies": {
    "lodash": "4.17.21",
    "event-stream": "3.3.7"
  }
}
```

Then run:

```bash
../../scripts/pounce-npm install
```

Expected result: Pounce scans the manifest and blocks before npm resolves or
installs dependencies.

Restore the original empty dependency object after this segment.

## Actual Install Mode

To prove the hook can allow real operations, unset dry-run mode and repeat the
safe install:

```bash
unset POUNCE_NPM_DRY_RUN
../../scripts/pounce-npm install lodash@4.17.21
```

For the risky dependency, keep the same command:

```bash
../../scripts/pounce-npm install event-stream@3.3.7
```

Pounce still blocks before npm executes.

## Show The Audit Trail

From the repository root:

```bash
tail -n 5 .pounce-sentinel/verdicts.jsonl
```

Use one blocked `auditId` to show explanation:

```bash
"$(bash scripts/resolve-python.sh)" services/policy-api/run_local.py explain <auditId>
```

Then show that exception handling is governed instead of silent bypass:

```bash
"$(bash scripts/resolve-python.sh)" services/policy-api/run_local.py exception <auditId> "demo-only isolated branch validation" --approver security-reviewer
```

## Judge-Facing Summary

Pounce Sentinel is not a passive scanner. It is a pre-action security checkpoint
for AI agents. Safe operations continue, suspicious operations warn, and risky
operations are blocked before the dependency is installed.
