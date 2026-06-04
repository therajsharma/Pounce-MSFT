# Real Threat Intelligence and Provenance Feeds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current seeded-only Pounce Sentinel intelligence path with real advisory, malware, provenance, freshness, and alerting behavior while preserving deterministic demo fallback data.

**Architecture:** Port the feed model from `therajsharma/Pounce` into the Azure policy API shape instead of copying the Codex plugin runtime wholesale. The policy API will evaluate dependency requests against a normalized feed, on-demand OSV results, and npm registry provenance metadata; feed state will be cached locally for tests/dev and persisted in Cosmos for Azure mode.

**Tech Stack:** Python 3.11, Azure Functions v4, Azure Cosmos DB, stdlib `urllib`, pytest, TypeScript/React/Vite dashboard.

---

## Initial Assessment Before Implementation

Before this implementation started, the repository did not implement real threat-intelligence or provenance feeds yet.

- `services/policy-api/pounce_sentinel/intel.py` contains only `SEEDED_INTEL` fixtures.
- `services/policy-api/pounce_sentinel/policy.py` calls only `find_seeded_record()` before falling back to exact-version demo policy.
- `services/policy-api/pounce_sentinel/api.py` returns hard-coded feed freshness rows from `service_status()`.
- `infra/bicep/main.bicep` creates Cosmos containers for `verdicts` and `exceptions`, but no feed-state container.

The reference repo implements reusable behavior in:

- `/tmp/pounce-ref.WpnMLo/plugins/pounce/scripts/pounce_intel.py`: normalized feed schema, GitHub advisory sync, OSV sync, hosted feed loading, cache precedence, stale warnings, on-demand OSV lookup.
- `/tmp/pounce-ref.WpnMLo/plugins/pounce/scripts/pounce_feed.py`: sync/export CLI.
- `/tmp/pounce-ref.WpnMLo/plugins/pounce/scripts/pounce_runtime.py`: npm registry metadata checks and provenance warning signals.

Important scope note: the reference repo does not appear to implement an SBOM policy feed; no `sbom`, `spdx`, or `cyclonedx` code paths were found. Treat SBOM as new work.

## Confirmed Implementation Decisions

- Feed persistence: add a dedicated Cosmos container named `feed_state`.
- Feed failure mode: warn/degrade in normal API and dashboard paths by default.
- Feed cadence: use a faster demo cadence rather than the reference repo's 6-hour production default.
- Hosted feed trust: accept HTTPS-only hosted JSON with redirects disabled and a 5 MiB response cap; label it `hosted_feed_unverified` unless signature verification is added later.
- SBOM scope for the first implementation: support an optional normalized policy artifact, not full CycloneDX/SPDX parsing.
- Feed sync control: add a manual authenticated feed-sync HTTP endpoint in addition to the timer trigger.

## File Structure

- Create `services/policy-api/pounce_sentinel/feeds.py`: normalized feed schema, local cache paths, hosted-feed loading, source precedence, stale warnings, package matching, feed-status projection.
- Create `services/policy-api/pounce_sentinel/feed_ingestion.py`: GitHub advisory sync, OSV sync, on-demand OSV lookup, normalized source metadata.
- Create `services/policy-api/pounce_sentinel/registry.py`: npm registry metadata lookup, missing provenance warning, provenance regression warning.
- Create `services/policy-api/pounce_sentinel/feed_sync.py`: orchestration used by CLI, Azure timer trigger, and tests.
- Create `services/policy-api/tests/test_feeds.py`: feed normalization, precedence, stale warning, package matching, hosted-feed transport boundary.
- Create `services/policy-api/tests/test_feed_ingestion.py`: mocked GitHub and OSV ingestion behavior.
- Create `services/policy-api/tests/test_registry.py`: mocked npm provenance behavior.
- Modify `services/policy-api/pounce_sentinel/policy.py`: evaluate normalized feed matches, on-demand OSV, npm provenance warnings, and seeded fallback.
- Modify `services/policy-api/pounce_sentinel/api.py`: dynamic feed status and optional feed sync endpoint if wanted.
- Modify `services/policy-api/pounce_sentinel/storage.py`: local feed-state read/write helpers.
- Modify `services/policy-api/pounce_sentinel/cosmos_storage.py`: Cosmos feed-state read/write helpers.
- Modify `services/policy-api/function_app.py`: add timer-triggered feed sync and optionally expose a manual admin sync route.
- Modify `infra/bicep/main.bicep`: add `feed_state` Cosmos container and app settings for feed configuration.
- Modify `services/policy-api/local.settings.json.sample` and `.env.example`: document feed env vars.
- Modify `apps/dashboard/src/types.ts`, `apps/dashboard/src/api.ts`, and `apps/dashboard/src/App.tsx`: display dynamic feed state, warnings, selected source, and item count.
- Modify `docs/implementation-status.md`, `docs/architecture.md`, and `docs/demo-runbook.md`: update status from seeded-only to real-feed-backed.

---

### Task 1: Feed Schema, Cache, and Matching

**Files:**
- Create: `services/policy-api/pounce_sentinel/feeds.py`
- Create: `services/policy-api/tests/test_feeds.py`
- Modify: `services/policy-api/pounce_sentinel/intel.py`

- [ ] **Step 1: Write failing feed normalization and matching tests**

Add tests that cover normalized artifacts, legacy seeded records, exact npm/PyPI package matches, revoked/expired item filtering, and stale warnings.

Run: `bash scripts/python-test.sh`
Expected: fail because `pounce_sentinel.feeds` does not exist.

- [ ] **Step 2: Implement normalized feed primitives**

Implement these public functions in `feeds.py`:

```python
normalize_ecosystem(value: object) -> str
normalize_package_name(ecosystem: str, name: str) -> str
normalize_feed_artifact(payload: object, *, observed_at: str | None = None, default_source: str = "feed") -> dict[str, object]
active_feed_items(items: list[dict[str, object]], *, at: datetime | None = None) -> list[dict[str, object]]
match_package_items(items: list[dict[str, object]], ecosystem: str, package_name: str, version: str) -> list[dict[str, object]]
```

Use the reference feed schema: `schema_version`, `generated_at`, `sources`, and `items`; item fields are `id`, `kind`, `match`, `action`, `confidence`, `reason`, `source`, `source_refs`, `published_at`, `modified_at`, `first_seen`, and `last_seen`.

- [ ] **Step 3: Implement runtime source precedence**

Implement these public functions in `feeds.py`:

```python
runtime_feed(feed_url: str | None = None) -> dict[str, object]
load_remote_feed(url: str) -> dict[str, object]
persist_feed_cache(feed: dict[str, object], *, fetched_at: str, fetched_from: str, path: Path | None = None) -> None
feed_status_rows(context: dict[str, object]) -> list[dict[str, object]]
```

Precedence must be: live hosted feed, hosted cache, local sync cache, seeded fallback. Hosted feed transport must be HTTPS-only, no credentials, no fragments, redirects disabled, and capped at 5 MiB.

- [ ] **Step 4: Run feed tests**

Run: `python -m pytest services/policy-api/tests/test_feeds.py -q`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add services/policy-api/pounce_sentinel/feeds.py services/policy-api/pounce_sentinel/intel.py services/policy-api/tests/test_feeds.py
git commit -m "feat: add normalized intelligence feed runtime"
```

### Task 2: Public Advisory and Malware Feed Ingestion

**Files:**
- Create: `services/policy-api/pounce_sentinel/feed_ingestion.py`
- Create: `services/policy-api/pounce_sentinel/feed_sync.py`
- Create: `services/policy-api/tests/test_feed_ingestion.py`
- Modify: `services/policy-api/requirements.txt` only if a non-stdlib dependency is explicitly approved; default is stdlib `urllib`.

- [ ] **Step 1: Write mocked ingestion tests**

Tests must assert:

- GitHub Global Security Advisories call `/advisories?type=malware&sort=updated&direction=asc`.
- GitHub pagination follows `Link: rel="next"`.
- OSV reads `modified_id.csv` and only expands `MAL-*` advisories for malware sync.
- OSV on-demand query normalizes `MAL-*` as `block` and non-malware advisories as `warn`.
- Sync persists `last_modified` checkpoints.

Run: `python -m pytest services/policy-api/tests/test_feed_ingestion.py -q`
Expected: fail because ingestion functions do not exist.

- [ ] **Step 2: Implement ingestion functions**

Implement:

```python
github_malware_items_since(last_modified: str | None) -> tuple[list[dict[str, object]], dict[str, object]]
osv_malware_items_since(last_modified: str | None) -> tuple[list[dict[str, object]], dict[str, object]]
on_demand_osv_items(ecosystem: str, package_name: str, version: str) -> list[dict[str, object]]
sync_public_intelligence() -> dict[str, object]
```

Environment variables:

- `POUNCE_GITHUB_TOKEN`
- `GITHUB_TOKEN`
- `POUNCE_VULNERABILITY_ACTION`, default `warn`

- [ ] **Step 3: Run ingestion tests**

Run: `python -m pytest services/policy-api/tests/test_feed_ingestion.py -q`
Expected: pass.

- [ ] **Step 4: Commit**

```bash
git add services/policy-api/pounce_sentinel/feed_ingestion.py services/policy-api/pounce_sentinel/feed_sync.py services/policy-api/tests/test_feed_ingestion.py
git commit -m "feat: sync public malware intelligence feeds"
```

### Task 3: Feed Freshness Persistence

**Files:**
- Modify: `services/policy-api/pounce_sentinel/storage.py`
- Modify: `services/policy-api/pounce_sentinel/cosmos_storage.py`
- Modify: `services/policy-api/tests/test_api.py`
- Modify: `infra/bicep/main.bicep`
- Modify: `services/policy-api/local.settings.json.sample`
- Modify: `.env.example`

- [ ] **Step 1: Write persistence tests**

Tests must assert local feed-state round trip and dynamic `service_status()["feeds"]` based on actual feed context instead of hard-coded demo rows.

Run: `python -m pytest services/policy-api/tests/test_api.py -q`
Expected: fail because status remains hard-coded.

- [ ] **Step 2: Add local and Cosmos feed-state helpers**

Add:

```python
storage.read_feed_state() -> dict[str, object] | None
storage.write_feed_state(state: dict[str, object]) -> None
cosmos_storage.read_feed_state() -> dict[str, object] | None
cosmos_storage.write_feed_state(state: dict[str, object]) -> None
```

Local path default: `.pounce-sentinel/feed-state.json`.

Cosmos container default: `feed_state`, partition key `/kind`, record id `feed-state-current`.

- [ ] **Step 3: Update Bicep and app settings**

Add a Cosmos container named `feed_state` and function app settings:

- `AZURE_COSMOS_FEED_STATE_CONTAINER`
- `POUNCE_IOC_FEED_URL`
- `POUNCE_FEED_STALE_AFTER_HOURS`
- `POUNCE_VULNERABILITY_ACTION`
- `POUNCE_FEED_FAILURE_MODE`

- [ ] **Step 4: Run persistence tests**

Run: `bash scripts/python-test.sh`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add services/policy-api/pounce_sentinel/storage.py services/policy-api/pounce_sentinel/cosmos_storage.py services/policy-api/tests/test_api.py infra/bicep/main.bicep services/policy-api/local.settings.json.sample .env.example
git commit -m "feat: persist feed freshness state"
```

### Task 4: Policy Integration and Provenance Warnings

**Files:**
- Create: `services/policy-api/pounce_sentinel/registry.py`
- Create: `services/policy-api/tests/test_registry.py`
- Modify: `services/policy-api/pounce_sentinel/policy.py`
- Modify: `services/policy-api/tests/test_policy.py`

- [ ] **Step 1: Write policy tests**

Tests must assert:

- Feed `action=block` package match returns `verdict=block`.
- Feed `action=warn` package match returns `verdict=warn`.
- On-demand OSV `MAL-*` result blocks when no cached feed has the package.
- npm package with missing `dist.attestations` warns.
- npm package where previous baseline had attestations but target does not emits `npm_provenance_regression`.
- Network verification failure returns `warn` with `verification_unavailable` evidence unless strict failure mode is enabled.

Run: `python -m pytest services/policy-api/tests/test_policy.py services/policy-api/tests/test_registry.py -q`
Expected: fail on missing behavior.

- [ ] **Step 2: Implement registry checks**

Implement:

```python
load_npm_package_index(package_name: str) -> dict[str, object]
check_npm_missing_provenance(package_name: str, version: str, metadata: dict[str, object]) -> list[dict[str, object]]
check_npm_provenance_regression(package_name: str, version: str, package_index: dict[str, object]) -> list[dict[str, object]]
registry_findings(ecosystem: str, package_name: str, version: str) -> list[dict[str, object]]
```

The first implementation only handles npm provenance. PyPI should keep OSV/advisory coverage without fake provenance claims.

- [ ] **Step 3: Update `vet_package()`**

Evaluation order:

1. Validate request.
2. Match normalized runtime feed.
3. Query on-demand OSV for exact npm/PyPI package.
4. Keep seeded fallback for deterministic demos.
5. Add npm provenance warnings.
6. Apply exact-version policy.
7. Return allow/warn/block with evidence and feed metadata.

- [ ] **Step 4: Run policy tests**

Run: `python -m pytest services/policy-api/tests/test_policy.py services/policy-api/tests/test_registry.py -q`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add services/policy-api/pounce_sentinel/registry.py services/policy-api/pounce_sentinel/policy.py services/policy-api/tests/test_policy.py services/policy-api/tests/test_registry.py
git commit -m "feat: use real feed and provenance signals in policy"
```

### Task 5: API, Timer Sync, and Dashboard Feed Health

**Files:**
- Modify: `services/policy-api/function_app.py`
- Modify: `services/policy-api/pounce_sentinel/api.py`
- Modify: `apps/dashboard/src/types.ts`
- Modify: `apps/dashboard/src/api.ts`
- Modify: `apps/dashboard/src/App.tsx`
- Modify: `apps/dashboard/src/App.test.tsx`

- [ ] **Step 1: Write API/dashboard tests**

Tests must assert `/v1/status` includes selected source, trust state, freshness timestamp, active item count, and warnings. Dashboard tests must render warning and stale feed rows without relying on fallback demo data.

Run: `pnpm test`
Expected: fail until API and dashboard are updated.

- [ ] **Step 2: Update API status**

Return dynamic feed rows with this shape:

```json
{
  "name": "osv",
  "status": "ok",
  "updatedAgo": "2h",
  "selectedFrom": "local_sync_cache",
  "trustState": "local_sync_cache",
  "activeItemCount": 42,
  "warnings": []
}
```

Keep `name`, `status`, and `updatedAgo` for backward compatibility.

- [ ] **Step 3: Add Azure timer trigger**

In `function_app.py`, add a timer trigger that calls `sync_public_intelligence()` every 6 hours and writes feed state. Keep failures non-fatal to the HTTP API, but persist warnings.

- [ ] **Step 4: Update dashboard types and rendering**

Extend `ServiceFeed` with optional `selectedFrom`, `trustState`, `activeItemCount`, and `warnings`. Keep the existing feed list UI but show stale or refresh-failure warnings in the status panel.

- [ ] **Step 5: Run API/dashboard tests**

Run: `pnpm test`
Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add services/policy-api/function_app.py services/policy-api/pounce_sentinel/api.py apps/dashboard/src/types.ts apps/dashboard/src/api.ts apps/dashboard/src/App.tsx apps/dashboard/src/App.test.tsx
git commit -m "feat: surface live feed health"
```

### Task 6: SBOM Policy Feed Adapter

**Files:**
- Modify: `services/policy-api/pounce_sentinel/feeds.py`
- Modify: `services/policy-api/tests/test_feeds.py`
- Modify: `docs/architecture.md`

- [ ] **Step 1: Write SBOM policy adapter tests**

Tests must assert an optional normalized feed item with `kind=sbom_policy` can warn or block an exact package, and unsupported SBOM formats are rejected with a clear warning instead of being parsed incorrectly.

Run: `python -m pytest services/policy-api/tests/test_feeds.py -q`
Expected: fail until adapter support exists.

- [ ] **Step 2: Implement first-pass SBOM policy support**

Support SBOM policy only through the same normalized feed artifact for this phase:

```json
{
  "id": "sbom-policy:npm:demo:1.2.3",
  "kind": "sbom_policy",
  "match": {"type": "package_exact", "ecosystem": "npm", "name": "demo", "version": "1.2.3"},
  "action": "warn",
  "reason": "Package is disallowed by organization SBOM policy.",
  "source": "sbom_policy",
  "source_refs": [{"kind": "policy", "id": "restricted-components"}]
}
```

Do not claim CycloneDX or SPDX ingestion in this task.

- [ ] **Step 3: Run SBOM adapter tests**

Run: `python -m pytest services/policy-api/tests/test_feeds.py -q`
Expected: pass.

- [ ] **Step 4: Commit**

```bash
git add services/policy-api/pounce_sentinel/feeds.py services/policy-api/tests/test_feeds.py docs/architecture.md
git commit -m "feat: add normalized SBOM policy feed support"
```

### Task 7: Documentation and End-to-End Verification

**Files:**
- Modify: `docs/implementation-status.md`
- Modify: `docs/demo-runbook.md`
- Modify: `docs/architecture.md`
- Modify: `README.md`

- [ ] **Step 1: Update docs**

Document:

- feed sources
- environment variables
- hosted feed transport boundary
- failure behavior
- stale threshold
- SBOM adapter limitation
- provenance warning semantics

- [ ] **Step 2: Run full verification**

Run:

```bash
bash scripts/python-test.sh
pnpm test
pnpm -r build
```

Expected: all pass.

- [ ] **Step 3: Run local smoke**

Run:

```bash
bash scripts/dev-smoke.sh
```

Expected: allow/warn/block cases still work and status includes live feed health rather than only seeded demo rows.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/implementation-status.md docs/demo-runbook.md docs/architecture.md
git commit -m "docs: document real feed integration"
```

---

## Clarifying Questions Before Execution

Resolved on 2026-06-04:

1. Use a new Cosmos container named `feed_state`.
2. Feed lookup failures warn/degrade by default.
3. First-pass normalized SBOM policy feed support is enough.
4. Use a faster demo cadence.
5. Add a manual authenticated feed-sync HTTP endpoint.

## Self-Review

- Spec coverage: advisory ingestion, malware ingestion, SBOM policy adapter, registry provenance, freshness persistence, failure behavior, and alerts are covered by Tasks 1-7.
- Placeholder scan: no `TBD`, `TODO`, or undefined "implement later" steps remain.
- Type consistency: feed rows retain `name`, `status`, `updatedAgo` and add optional fields, so dashboard compatibility is preserved.
